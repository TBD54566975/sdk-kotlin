/*
 * Message.kt
 *
 * This code was generated by json-kotlin-schema-codegen - JSON Schema Code Generator
 * See https://github.com/pwall567/json-kotlin-schema-codegen
 *
 * It is not advisable to modify generated code as any modifications will be lost
 * when the generation process is re-run.
 *
 * This file was generated from tbdex-protocol/json-schemas. You can regenerate by running `./gradlew generate`
 */
package tbdex.model

data class Message(
    val metadata: Metadata,
    /** The actual message content */
    val data: Data,
    /** Signature that verifies the authenticity and integrity of a message */
    val signature: String,
    val private: Private? = null
) {

    data class Metadata(
        /** The sender's DID */
        val from: String,
        /** The recipient's DID */
        val to: String,
        /** The message kind (e.g. rfq, quote) */
        val kind: Kind,
        /** The message ID */
        val id: String,
        /** ID for a 'thread' of messages between Alice <-> PFI. Set by the first message in a thread */
        val exchangeId: String,
        /** ISO8601 formatted string representing the timestamp */
        val createdAt: String
    ) {

        init {
            require(cg_regex0.containsMatchIn(from)) { "from does not match pattern $cg_regex0 - $from" }
            require(cg_regex0.containsMatchIn(to)) { "to does not match pattern $cg_regex0 - $to" }
        }

    }

    /**
     * The message kind (e.g. rfq, quote)
     */
    enum class Kind {
        rfq,
        quote,
        order,
        orderStatus,
        close
    }

    /**
     * The actual message content
     */
    open class Data

    open class Private

    companion object {
        private val cg_regex0 = Regex("^did:([a-z0-9]+):((?:(?:[a-zA-Z0-9._-]|(?:%[0-9a-fA-F]{2}))*:)*((?:[a-zA-Z0-9._-]|(?:%[0-9a-fA-F]{2}))+))((;[a-zA-Z0-9_.:%-]+=[a-zA-Z0-9_.:%-]*)*)(/[^#?]*)?([?][^#]*)?(#.*)?\$")
    }

}
