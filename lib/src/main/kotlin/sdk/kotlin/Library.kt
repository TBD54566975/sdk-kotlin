package sdk.kotlin

import com.danubetech.verifiablecredentials.jwt.JwtVerifiableCredential
import com.danubetech.verifiablecredentials.jwt.ToJwtConverter
import com.identityfoundry.ddi.protocol.multicodec.Multicodec
import com.identityfoundry.ddi.protocol.multicodec.MulticodecEncoder
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import io.ipfs.multibase.Multibase
import java.net.URI
import java.util.*

public class DIDKey {
    public companion object {
        public fun generateEd25519(): Pair<OctetKeyPair, String> {
            val jwk = OctetKeyPairGenerator(Curve.Ed25519)
                .keyID("123")
                .generate()
            val publicJWK = jwk.toPublicJWK()

            return Pair(
                jwk,
                "did:key:" + Multibase.encode(
                    Multibase.Base.Base58BTC,
                    MulticodecEncoder.encode(Multicodec.ED25519_PUB, publicJWK.decodedX)
                )
            )
        }
    }
}

public data class SignOptions(
    val kid: String,
    val issuerDid: String,
    val subjectDid: String,
    val signerPrivateKey: OctetKeyPair,
)

// TODO: Implement CredentialSchema,
public data class CreateVcOptions(
    val credentialSubject: CredentialSubject,
    val issuer: String,
    val expirationDate: Date?,
    val credentialStatus: CredentialStatus?,
)

public data class CreateVpOptions(
    val presentationDefinition: PresentationDefinitionV2,
    val verifiableCredentialJwts: List<String>,
)

public typealias VcJwt = String

public class VerifiableCredential {
    public companion object {
        @Throws(Exception::class)
        public fun create(
            signOptions: SignOptions,
            createVcOptions: CreateVcOptions?,
            verifiableCredential: VerifiableCredentialType?,
        ): VcJwt {
            if (createVcOptions != null && verifiableCredential != null) {
                throw Exception("options and verifiableCredentials are mutually exclusive, either include the full verifiableCredential or the options to create one")
            }

            if (createVcOptions == null && verifiableCredential == null) {
                throw Exception("options or verifiableCredential must be provided")
            }

            val vc: VerifiableCredentialType = verifiableCredential ?: VerifiableCredentialType.builder()
                .id(URI.create(UUID.randomUUID().toString()))
                .context(URI.create("https://www.w3.org/2018/credentials/v1"))
                .type("VerifiableCredential")
                .credentialSubject(createVcOptions!!.credentialSubject)
                .issuer(URI.create(createVcOptions.issuer))
                .issuanceDate(Date())
                .apply {
                    createVcOptions.expirationDate?.let { expirationDate(it) }
                    createVcOptions.credentialStatus?.let { credentialStatus(it) }
                }
                .build()

            // TODO: Implement: validatePayload(vc)
            return ToJwtConverter.toJwtVerifiableCredential(vc).sign_Ed25519_EdDSA(signOptions.signerPrivateKey)
        }

        public fun verify(publicKey: OctetKeyPair, vcJWT: String): Boolean {
            return JwtVerifiableCredential.fromCompactSerialization(vcJWT).verify_Ed25519_EdDSA(publicKey)
        }
    }
}

// TODO: Implement this
public class VerifiablePresentation {
    public companion object {
        public fun create(signOptions: SignOptions, createVpOptions: CreateVpOptions?): String? {
            if (createVpOptions == null) {
                val vp: com.danubetech.verifiablecredentials.VerifiablePresentation =
                    com.danubetech.verifiablecredentials.VerifiablePresentation.builder().build()
                return ToJwtConverter.toJwtVerifiablePresentation(vp).sign_Ed25519_EdDSA(signOptions.signerPrivateKey)
            }
            throw NotImplementedError("create does not support createVpOptions")
        }

        public fun verify(publicKey: OctetKeyPair, vcJWT: String): Boolean {
            require(!publicKey.isPrivate)
            require(vcJWT.isNotEmpty())
            throw NotImplementedError("verify is not implemented yet")
        }
    }
}