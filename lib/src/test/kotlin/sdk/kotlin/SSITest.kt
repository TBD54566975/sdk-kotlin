package sdk.kotlin

import java.net.URI
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertTrue
import kotlin.test.assertNotNull

class SSITest {

    @Test
    fun generateReturnsValidKey() {
        assertContains(DIDKey.generateEd25519().second, "did:key:z6Mk")
    }

    @Test
    fun `creates a VC JWT with CreateVCOptions`() {
        val didKey = DIDKey.generateEd25519();
        val subjectIssuerDid = didKey.second

        val claims: MutableMap<String, Any> = LinkedHashMap()
        val degree: MutableMap<String, Any> = LinkedHashMap()
        degree["name"] = "Bachelor of Science and Arts"
        degree["type"] = "BachelorDegree"
        claims["college"] = "Test University"
        claims["degree"] = degree

        val credentialSubject = CredentialSubject.builder()
            .id(URI.create(didKey.second))
            .claims(claims)
            .build()

        val vcCreateOptions = CreateVcOptions(
            credentialSubject = credentialSubject,
            issuer = subjectIssuerDid,
            expirationDate = null,
            credentialStatus = null
        )

        val signOptions = SignOptions(
            kid = "123",
            issuerDid = subjectIssuerDid,
            subjectDid = subjectIssuerDid,
            signerPrivateKey = didKey.first
        )

        val vcJwt: VcJwt = VerifiableCredential.create(signOptions, vcCreateOptions, null)

        assertNotNull(vcJwt)
        assertTrue { vcJwt.split(".").size == 3 }

        val parts = vcJwt.split(".")
        val header = String(Base64.getDecoder().decode(parts[0]))
        val payload = String(Base64.getDecoder().decode(parts[1]))

        // Header Checks
        assertTrue { header.contains("\"alg\":\"") }
        assertTrue { header.contains("\"typ\":\"JWT\"") }

        // Payload Checks
        assertTrue { payload.contains("\"iss\":\"") }
        assertTrue { payload.contains("\"sub\":\"") }

        assertTrue {
            VerifiableCredential.verify(signOptions.signerPrivateKey.toPublicJWK(), vcJwt)
        }
    }

}