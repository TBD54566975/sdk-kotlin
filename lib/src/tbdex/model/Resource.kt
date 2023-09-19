/*
 * Resource.kt
 *
 * This code was generated by json-kotlin-schema-codegen - JSON Schema Code Generator
 * See https://github.com/pwall567/json-kotlin-schema-codegen
 *
 * It is not advisable to modify generated code as any modifications will be lost
 * when the generation process is re-run.
 *
 * This file was generated from tbdex-protocol/json-schemas. Run gradle generate
 */
package tbdex.model

/**
 * ResourceModel
 */
data class Resource(
    /** The metadata object contains fields about the resource and is present for every tbdex resources of all types. */
    val metadata: Metadata,
    /** The actual resource content */
    val data: Data,
    /** Signature that verifies that authenticity and integrity of a message */
    val signature: String
) {

    /**
     * The metadata object contains fields about the resource and is present for every tbdex resources of all types.
     */
    data class Metadata(
        /** The PFI's DID */
        val from: String,
        /** The resource kind (e.g. Offering) */
        val kind: Kind,
        /** The resource id */
        val id: String,
        /** When the resource was created at. Expressed as ISO8601 */
        val createdAt: String,
        /** When the resource was last updated. Expressed as ISO8601 */
        val updatedAt: String? = null
    ) {

        init {
            require(cg_regex0.containsMatchIn(from)) { "from does not match pattern $cg_regex0 - $from" }
        }

    }

    /**
     * The resource kind (e.g. Offering)
     */
    enum class Kind {
        offering
    }

    /**
     * The actual resource content
     */
    open class Data

    companion object {
        private val cg_regex0 = Regex("^did:([a-z0-9]+):((?:(?:[a-zA-Z0-9._-]|(?:%[0-9a-fA-F]{2}))*:)*((?:[a-zA-Z0-9._-]|(?:%[0-9a-fA-F]{2}))+))((;[a-zA-Z0-9_.:%-]+=[a-zA-Z0-9_.:%-]*)*)(/[^#?]*)?([?][^#]*)?(#.*)?\$")
    }

}
