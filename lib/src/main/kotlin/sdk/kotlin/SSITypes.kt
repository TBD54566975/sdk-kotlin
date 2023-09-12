package sdk.kotlin

typealias CredentialSubject = com.danubetech.verifiablecredentials.CredentialSubject
typealias VerifiableCredentialType = com.danubetech.verifiablecredentials.VerifiableCredential
typealias CredentialStatus = com.danubetech.verifiablecredentials.credentialstatus.CredentialStatus

data class PresentationDefinitionV2(
    val id: String,
    val name: String?,
    val purpose: String?,
    val format: Format?,
    val inputDescriptors: List<InputDescriptorV2>,
    val frame: Map<String, Any>?
)

data class Format(
    val jwt: JwtObject?,
    val jwtVc: JwtObject?,
    val jwtVp: JwtObject?,
)

data class JwtObject(
    val alg: List<String>
)

data class InputDescriptorV2(
    val id: String,
    val name: String?,
    val purpose: String?,
    val group: List<String>?,
    val issuance: List<Issuance>?,
    val constraints: ConstraintsV2?
)

data class Issuance(
    val manifest: String?,
    val entries: Map<String, Any>
)

data class ConstraintsV2(
    val fields: List<FieldV2>?,
)

data class FieldV2(
    val id: String?,
    val path: List<String>?,
    val purpose: String?,
    val name: String?
)