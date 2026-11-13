package com.sap.cpi.pqc

import com.sap.gateway.ip.core.customdev.util.Message
import groovy.json.JsonSlurper
import spock.lang.Specification

class QuantumSafeLedgerSyncSpec extends Specification {

    QuantumSafeLedgerSync pqcSync = new QuantumSafeLedgerSync()
    Message message = Mock(Message)

    def "Should seal central bank clearing payload using Hybrid X25519 + ML-KEM-768 and sign with ML-DSA-65"() {
        given: "An ISO 20022 pacs.009 interbank settlement payload"
        def clearingJson = """
        {
            "settlementId": "CB-SETTLE-2026-998172",
            "centralBankBic": "DEUTDEFFXXX",
            "amount": 1250000000.00,
            "currency": "EUR"
        }
        """
        message.getBody(String.class) >> clearingJson
        message.getHeaders() >> ["X-PQC-Handshake-Mode": "HYBRID-X25519-MLKEM768"]

        when: "The SAP CPI PQC engine executes hybrid key derivation and Dilithium signing"
        pqcSync.processData(message)

        then: "FIPS 203/204 headers and sealed S/4HANA AFC payload are generated"
        1 * message.setHeader("X-PQC-Quantum-Safe-Verified", "true")
        1 * message.setHeader("X-PQC-Compliance-Tier", "FIPS-140-3-HYBRID-LEVEL-3")
        1 * message.setHeader("X-PQC-KEM-Algorithm", "X25519+ML-KEM-768")
        1 * message.setHeader("X-PQC-DSA-Algorithm", "ML-DSA-65")
        1 * message.setHeader("X-TSA-Timestamp-UTC", _ as String)
        1 * message.setHeader("CamelHttpResponseCode", 200)
        1 * message.setBody(_ as String) >> { args ->
            def parsed = new JsonSlurper().parseText(args[0])
            assert parsed.quantumSafeLedgerSync.cryptographicProof.mlKemEncapsulationBytes == 1088
            assert parsed.quantumSafeLedgerSync.cryptographicProof.mlDsaSignatureBytes == 3309
        }
    }

    def "Should block classical-only RSA/ECDHE downgrade attempts with HTTP 426"() {
        given: "A settlement request attempting classical RSA-2048 without PQC"
        message.getBody(String.class) >> '{"settlementId":"CB-01","centralBankBic":"FRNYUS33","amount":500000,"currency":"USD"}'
        message.getHeaders() >> ["X-PQC-Handshake-Mode": "CLASSICAL-RSA-2048"]

        when: "The anti-downgrade check runs"
        pqcSync.processData(message)

        then: "The request is rejected with HTTP 426 Upgrade Required"
        1 * message.setHeader("X-PQC-Quantum-Safe-Verified", "false")
        1 * message.setHeader("CamelHttpResponseCode", 426)
    }
}
