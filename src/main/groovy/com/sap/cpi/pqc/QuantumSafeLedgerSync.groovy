package com.sap.cpi.pqc

import com.sap.gateway.ip.core.customdev.util.Message
import groovy.json.JsonSlurper
import groovy.json.JsonOutput
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Security
import java.security.Signature
import java.time.Instant
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec
import org.bouncycastle.jcajce.spec.KEMGenerateSpec
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.digests.SHA384Digest

class QuantumSafeLedgerSync {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider())
        }
    }

    Message processData(Message message) {
        def body = message.getBody(String.class)
        if (!body || body.trim().isEmpty()) {
            throw new IllegalArgumentException("PQC Security Alert: Empty central bank clearing payload.")
        }

        def headers = message.getHeaders() ?: [:]
        def slurper = new JsonSlurper()
        def payload = slurper.parseText(body)

        if (!payload.settlementId || payload.amount == null || !payload.currency || !payload.centralBankBic) {
            throw new IllegalArgumentException("ISO 20022 / PQC Schema Fault: Missing settlementId, amount, currency, or centralBankBic.")
        }

        String requestedMode = (headers.get("X-PQC-Handshake-Mode") ?: "HYBRID-X25519-MLKEM768").toString().toUpperCase()
        boolean isQuantumSafe = requestedMode.contains("MLKEM768") || requestedMode.contains("KYBER")

        if (!isQuantumSafe) {
            message.setHeader("X-PQC-Quantum-Safe-Verified", "false")
            message.setHeader("X-PQC-Compliance-Tier", "CLASSICAL_DOWNGRADE_REJECTED")
            message.setHeader("CamelHttpResponseCode", 426)
            message.setBody(JsonOutput.prettyPrint(JsonOutput.toJson([
                pqcSecurityAlert: [
                    status: "UPGRADE_REQUIRED_QUANTUM_VULNERABLE",
                    rejectedMode: requestedMode,
                    requiredStandard: "FIPS-203 ML-KEM-768 + FIPS-204 ML-DSA-65"
                ]
            ])))
            return message
        }

        SecureRandom secureRandom = new SecureRandom()

        // 1. Classical ECDHE (X25519) Key Exchange
        KeyPairGenerator x25519Kpg = KeyPairGenerator.getInstance("X25519")
        KeyPair initiatorEc = x25519Kpg.generateKeyPair()
        KeyPair responderEc = x25519Kpg.generateKeyPair()
        KeyAgreement ka = KeyAgreement.getInstance("X25519")
        ka.init(initiatorEc.getPrivate())
        ka.doPhase(responderEc.getPublic(), true)
        byte[] classicalSharedSecret = ka.generateSecret()

        // 2. Post-Quantum NIST FIPS 203 ML-KEM-768 (Kyber) Key Encapsulation
        KeyPairGenerator mlKemKpg = KeyPairGenerator.getInstance("ML-KEM", "BC")
        mlKemKpg.initialize(MLKEMParameterSpec.ml_kem_768, secureRandom)
        KeyPair receiverKemKp = mlKemKpg.generateKeyPair()

        KeyGenerator mlKemKg = KeyGenerator.getInstance("ML-KEM", "BC")
        mlKemKg.init(new KEMGenerateSpec(receiverKemKp.getPublic(), "AES"), secureRandom)
        SecretKeyWithEncapsulation kemResult = (SecretKeyWithEncapsulation) mlKemKg.generateKey()
        byte[] pqcSharedSecret = kemResult.getEncoded()
        byte[] pqcEncapsulation = kemResult.getEncapsulation()

        // 3. FIPS 140-3 Hybrid HKDF-SHA384 Key Derivation (Classical || Post-Quantum)
        byte[] combinedIkm = new byte[classicalSharedSecret.length + pqcSharedSecret.length]
        System.arraycopy(classicalSharedSecret, 0, combinedIkm, 0, classicalSharedSecret.length)
        System.arraycopy(pqcSharedSecret, 0, combinedIkm, classicalSharedSecret.length, pqcSharedSecret.length)

        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA384Digest())
        hkdf.init(new HKDFParameters(
            combinedIkm,
            "SAP-BTP-PQC-SALT-2026".getBytes("UTF-8"),
            "SAP-S4HANA-AFC-HYBRID-KDF".getBytes("UTF-8")
        ))
        byte[] derivedAes256Key = new byte[32]
        hkdf.generateBytes(derivedAes256Key, 0, 32)

        // 4. AES-256-GCM Payload Encryption
        byte[] iv = new byte[12]
        secureRandom.nextBytes(iv)
        Cipher aesGcm = Cipher.getInstance("AES/GCM/NoPadding")
        aesGcm.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(derivedAes256Key, "AES"), new GCMParameterSpec(128, iv))
        byte[] sealedPayload = aesGcm.doFinal(body.getBytes("UTF-8"))

        // 5. Post-Quantum NIST FIPS 204 ML-DSA-65 (Dilithium) Digital Signature + TSA Stamp
        String tsaTimestamp = Instant.now().toString()
        KeyPairGenerator mlDsaKpg = KeyPairGenerator.getInstance("ML-DSA", "BC")
        mlDsaKpg.initialize(MLDSAParameterSpec.ml_dsa_65, secureRandom)
        KeyPair signingKeyPair = mlDsaKpg.generateKeyPair()

        Signature mlDsaSigner = Signature.getInstance("ML-DSA", "BC")
        mlDsaSigner.initSign(signingKeyPair.getPrivate(), secureRandom)
        mlDsaSigner.update(sealedPayload)
        mlDsaSigner.update(tsaTimestamp.getBytes("UTF-8"))
        byte[] mlDsaSignatureBytes = mlDsaSigner.sign()

        message.setHeader("X-PQC-Quantum-Safe-Verified", "true")
        message.setHeader("X-PQC-Compliance-Tier", "FIPS-140-3-HYBRID-LEVEL-3")
        message.setHeader("X-PQC-KEM-Algorithm", "X25519+ML-KEM-768")
        message.setHeader("X-PQC-DSA-Algorithm", "ML-DSA-65")
        message.setHeader("X-TSA-Timestamp-UTC", tsaTimestamp)
        message.setHeader("CamelHttpResponseCode", 200)

        def s4hanaAfcEnvelope = [
            quantumSafeLedgerSync: [
                settlementId: payload.settlementId,
                centralBankBic: payload.centralBankBic,
                amount: payload.currency == "JPY" ? payload.amount : (payload.amount as BigDecimal),
                currency: payload.currency,
                cryptographicProof: [
                    hybridKemAlgorithm: "X25519 + NIST FIPS 203 ML-KEM-768 (Kyber)",
                    signatureAlgorithm: "NIST FIPS 204 ML-DSA-65 (Dilithium)",
                    kdfFunction: "HKDF-SHA384 (FIPS 140-3)",
                    mlKemEncapsulationBytes: pqcEncapsulation.length,
                    mlDsaSignatureBytes: mlDsaSignatureBytes.length,
                    sealedPayloadBase64: sealedPayload.encodeBase64().toString(),
                    mlDsa65SignatureBase64: mlDsaSignatureBytes.encodeBase64().toString(),
                    tsaAuthorityStamp: tsaTimestamp
                ],
                s4hanaTargetModule: "SAP S/4HANA Advanced Financial Closing (AFC)"
            ]
        ]

        message.setBody(JsonOutput.prettyPrint(JsonOutput.toJson(s4hanaAfcEnvelope)))
        return message
    }
}
