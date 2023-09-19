/*
 * Quote.kt
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

data class Quote(
    /** When this quote expires. Expressed as ISO8601 */
    val expiresAt: String,
    val base: Base,
    val quote: Base,
    val paymentInstructions: PaymentInstructions
) {

    data class Base(
        /** ISO 3166 currency code string */
        val currencyCode: String,
        /** The amount of currency expressed in the smallest respective unit */
        val amountSubunits: String,
        /** The amount paid in fees */
        val feeSubunits: String
    )

    data class PaymentInstructions(
        val payin: Payin? = null,
        val payout: Payin? = null
    )

    data class Payin(
        /** Link to allow Alice to pay PFI, or be paid by the PFI */
        val link: String? = null,
        /** Instruction on how Alice can pay PFI, or how Alice can be paid by the PFI */
        val instruction: String? = null
    )

}
