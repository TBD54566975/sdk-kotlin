package sdk.kotlin

import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.assertContains

class DIDKeyTest {
    @Test fun generateReturnsValidKey() {
        assertContains(DIDKey.generateEd25519().second, "did:key:z6Mk")
    }
}
