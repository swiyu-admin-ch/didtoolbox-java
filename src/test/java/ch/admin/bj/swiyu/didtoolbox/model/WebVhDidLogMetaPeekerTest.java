package ch.admin.bj.swiyu.didtoolbox.model;

// TODO import ch.admin.eid.didresolver.Did;

import ch.admin.bj.swiyu.didtoolbox.AbstractUtilTestBase;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.jupiter.api.Assertions.*;

class WebVhDidLogMetaPeekerTest extends AbstractUtilTestBase {

    private static Collection<Object[]> invalidDidLogEntries() {
        return Arrays.asList(new String[][]{
                /*
                TODO cover other cases like:
                - "Every versionId MUST be a dash-separated combination of version number and entry hash, found: ..."
                - "The versionTime MUST be a valid ISO8601 date/time string"
                - "DID doc ID is missing"
                 */
                {"[]", "Malformed DID log entry"},
                {"""
                        {"versionTime": "2025-04-29T17:15:59Z", "parameters": {"witness": {"threshold": 2, "witnesses": [{"id": "did:key:z6MknJjDn4BuvPrr3nG9GhmdbeiCGT27KJumPXz9i7Q3LobW", "weight": 1}, {"id": "did:key:z6MkvXRkuaGJgDzmRY7XFwUWGt8PccUdHrknR3oUwB42LjS9", "weight": 1}, {"id": "did:key:z6MkhkfmcK42GN8DVNxjyYtAgyn21EsXAowNhUPzmGppcVfS", "weight": 1}]}, "updateKeys": ["z6MkhgLHMevgX5xE69NLJrm1vPFCWRSZfuBgfJPkUAfj8bGZ"], "method": "did:webvh:0.5", "scid": "QmQyDxVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmQyDxVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkhgLHMevgX5xE69NLJrm1vPFCWRSZfuBgfJPkUAfj8bGZ#z6MkhgLHMevgX5xE69NLJrm1vPFCWRSZfuBgfJPkUAfj8bGZ", "created": "2025-04-29T17:15:59Z", "proofPurpose": "assertionMethod", "proofValue": "z4ggCRSgjGoEwaTTGAz7JHz4h1k3Afp8hzDC2DyHe7riEULVriRwHLdf8gA3VR1xXEHxKkz9ikrX25YPYsVtWZMCG"}]}""",
                        "Missing versionId"},
                {"""
                        {"versionId": "1-QmV8pidQB1moYe2AKjNvi2bQghv8Gah18794HrGki1yXQw", "parameters": {"witness": {"threshold": 2, "witnesses": [{"id": "did:key:z6MknJjDn4BuvPrr3nG9GhmdbeiCGT27KJumPXz9i7Q3LobW", "weight": 1}, {"id": "did:key:z6MkvXRkuaGJgDzmRY7XFwUWGt8PccUdHrknR3oUwB42LjS9", "weight": 1}, {"id": "did:key:z6MkhkfmcK42GN8DVNxjyYtAgyn21EsXAowNhUPzmGppcVfS", "weight": 1}]}, "updateKeys": ["z6MkhgLHMevgX5xE69NLJrm1vPFCWRSZfuBgfJPkUAfj8bGZ"], "method": "did:webvh:0.5", "scid": "QmQyDxVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmQyDxVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkhgLHMevgX5xE69NLJrm1vPFCWRSZfuBgfJPkUAfj8bGZ#z6MkhgLHMevgX5xE69NLJrm1vPFCWRSZfuBgfJPkUAfj8bGZ", "created": "2025-04-29T17:15:59Z", "proofPurpose": "assertionMethod", "proofValue": "z4ggCRSgjGoEwaTTGAz7JHz4h1k3Afp8hzDC2DyHe7riEULVriRwHLdf8gA3VR1xXEHxKkz9ikrX25YPYsVtWZMCG"}]}""",
                        "Missing versionTime"},
                {"""
                        {"versionId": "1-QmV8pidQB1moYe2AKjNvi2bQghv8Gah18794HrGki1yXQw", "versionTime": "2025-04-29T17:15:59Z", "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmQyDxVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkhgLHMevgX5xE69NLJrm1vPFCWRSZfuBgfJPkUAfj8bGZ#z6MkhgLHMevgX5xE69NLJrm1vPFCWRSZfuBgfJPkUAfj8bGZ", "created": "2025-04-29T17:15:59Z", "proofPurpose": "assertionMethod", "proofValue": "z4ggCRSgjGoEwaTTGAz7JHz4h1k3Afp8hzDC2DyHe7riEULVriRwHLdf8gA3VR1xXEHxKkz9ikrX25YPYsVtWZMCG"}]}""",
                        "Missing parameters"},
                {"""
                        {"versionId": "1-QmV8pidQB1moYe2AKjNvi2bQghv8Gah18794HrGki1yXQw", "versionTime": "2025-04-29T17:15:59Z", "parameters": {"witness": {"threshold": 2, "witnesses": [{"id": "did:key:z6MknJjDn4BuvPrr3nG9GhmdbeiCGT27KJumPXz9i7Q3LobW", "weight": 1}, {"id": "did:key:z6MkvXRkuaGJgDzmRY7XFwUWGt8PccUdHrknR3oUwB42LjS9", "weight": 1}, {"id": "did:key:z6MkhkfmcK42GN8DVNxjyYtAgyn21EsXAowNhUPzmGppcVfS", "weight": 1}]}, "updateKeys": ["z6MkhgLHMevgX5xE69NLJrm1vPFCWRSZfuBgfJPkUAfj8bGZ"], "method": "did:webvh:0.5", "scid": "QmQyDxVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkhgLHMevgX5xE69NLJrm1vPFCWRSZfuBgfJPkUAfj8bGZ#z6MkhgLHMevgX5xE69NLJrm1vPFCWRSZfuBgfJPkUAfj8bGZ", "created": "2025-04-29T17:15:59Z", "proofPurpose": "assertionMethod", "proofValue": "z4ggCRSgjGoEwaTTGAz7JHz4h1k3Afp8hzDC2DyHe7riEULVriRwHLdf8gA3VR1xXEHxKkz9ikrX25YPYsVtWZMCG"}]}""",
                        "Missing DID document"},
                {"""
                        {"versionId": "1-QmV8pidQB1moYe2AKjNvi2bQghv8Gah18794HrGki1yXQw", "versionTime": "2025-04-29T17:15:59Z", "parameters": {"witness": {"threshold": 2, "witnesses": [{"id": "did:key:z6MknJjDn4BuvPrr3nG9GhmdbeiCGT27KJumPXz9i7Q3LobW", "weight": 1}, {"id": "did:key:z6MkvXRkuaGJgDzmRY7XFwUWGt8PccUdHrknR3oUwB42LjS9", "weight": 1}, {"id": "did:key:z6MkhkfmcK42GN8DVNxjyYtAgyn21EsXAowNhUPzmGppcVfS", "weight": 1}]}, "updateKeys": ["z6MkhgLHMevgX5xE69NLJrm1vPFCWRSZfuBgfJPkUAfj8bGZ"], "method": "did:webvh:0.5", "scid": "QmQyDxVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmQyDxVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn:domain.example"}}""",
                        "Missing DID integrity proof"}}
        );
    }

    @DisplayName("Peeking (into invalid did:webvh log entry) for various invalidDidLogEntry variants")
    @ParameterizedTest(name = "Expected exception ''{1}'' thrown for invalidDidLogEntry: {0}")
    @MethodSource("invalidDidLogEntries")
    void testThrowsDidLogMetaPeekerException(String invalidDidLogEntry, String containedInExcMessage) {

        var exc = assertThrowsExactly(DidLogMetaPeekerException.class, () -> {
            WebVhDidLogMetaPeeker.peek(invalidDidLogEntry);
        });
        assertTrue(exc.getMessage().contains(containedInExcMessage));
    }

    @Test
    void testPeekExample() {

        DidLogMeta meta = null;
        try {
            // as suggested by https://didwebvh.info/latest/example/#did-log-file-for-version-2
            meta = WebVhDidLogMetaPeeker.peek("""
                    {"versionId": "1-QmV8pidQB1moYe2AKjNvi2bQghv8Gah18794HrGki1yXQw", "versionTime": "2025-04-29T17:15:59Z", "parameters": {"witness": {"threshold": 2, "witnesses": [{"id": "did:key:z6MknJjDn4BuvPrr3nG9GhmdbeiCGT27KJumPXz9i7Q3LobW", "weight": 1}, {"id": "did:key:z6MkvXRkuaGJgDzmRY7XFwUWGt8PccUdHrknR3oUwB42LjS9", "weight": 1}, {"id": "did:key:z6MkhkfmcK42GN8DVNxjyYtAgyn21EsXAowNhUPzmGppcVfS", "weight": 1}]}, "updateKeys": ["z6MkhgLHMevgX5xE69NLJrm1vPFCWRSZfuBgfJPkUAfj8bGZ"], "method": "did:webvh:0.5", "scid": "QmQyDxVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmQyDxVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkhgLHMevgX5xE69NLJrm1vPFCWRSZfuBgfJPkUAfj8bGZ#z6MkhgLHMevgX5xE69NLJrm1vPFCWRSZfuBgfJPkUAfj8bGZ", "created": "2025-04-29T17:15:59Z", "proofPurpose": "assertionMethod", "proofValue": "z4ggCRSgjGoEwaTTGAz7JHz4h1k3Afp8hzDC2DyHe7riEULVriRwHLdf8gA3VR1xXEHxKkz9ikrX25YPYsVtWZMCG"}]}
                    {"versionId": "2-QmaFkyeG4Rksig3tjyn2qQu3eCVeoAZ5txLT4RwyLZZ6ur", "versionTime": "2025-04-29T17:15:59Z", "parameters": {}, "state": {"@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1", "https://identity.foundation/.well-known/did-configuration/v1"], "id": "did:webvh:QmQyDxVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn:domain.example", "authentication": ["did:webvh:QmQyDxVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn:domain.example#z6MkjdhTMxysig1P8n3SjnqMCKSR83n3QWqCCioXj12Q3vmk"], "assertionMethod": ["did:webvh:QmQyDxVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn:domain.example#z6MkjdhTMxysig1P8n3SjnqMCKSR83n3QWqCCioXj12Q3vmk"], "verificationMethod": [{"id": "did:webvh:QmQyDxVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn:domain.example#z6MkjdhTMxysig1P8n3SjnqMCKSR83n3QWqCCioXj12Q3vmk", "controller": "did:webvh:QmQyDxVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn:domain.example", "type": "Multikey", "publicKeyMultibase": "z6MkjdhTMxysig1P8n3SjnqMCKSR83n3QWqCCioXj12Q3vmk"}], "service": [{"id": "did:webvh:QmQyDxVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn:domain.example#domain", "type": "LinkedDomains", "serviceEndpoint": "https://domain.example"}]}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkhgLHMevgX5xE69NLJrm1vPFCWRSZfuBgfJPkUAfj8bGZ#z6MkhgLHMevgX5xE69NLJrm1vPFCWRSZfuBgfJPkUAfj8bGZ", "created": "2025-04-29T17:15:59Z", "proofPurpose": "assertionMethod", "proofValue": "z2SVXskwV5w5tVGwijWSUQbAUswXxZLbtm5KokNqX9XMqsgTSrQShMAZHedqET6u2wtNrY4ceqA1qgwL5ZPx8D4sP"}]}
                    """); // MUT
            assertNotNull(meta);
            assertNotNull(meta.getDidDocId());
            // TODO new Did(meta.didDocId); // ultimate test

        } catch (Exception e) {
            fail(e);
        }

        assertNotNull(meta.getLastVersionId());
        assertNotNull(meta.getDateTime());
        assertEquals(2, meta.lastVersionNumber);
        assertNotNull(meta.getParams());
        assertNotNull(meta.getParams().method);
        assertNotNull(meta.getParams().scid);
        assertNotNull(meta.getParams().updateKeys);
        assertFalse(meta.getParams().updateKeys.isEmpty());
        assertEquals(1, meta.getParams().updateKeys.size());
    }

    @Test
    void testPeekGenerated() {

        DidLogMeta meta = null;
        try {
            meta = WebVhDidLogMetaPeeker.peek(buildWebVhDidLog(TEST_VERIFICATION_METHOD_KEY_PROVIDER_JKS)); // MUT
            assertNotNull(meta);
            assertNotNull(meta.getDidDocId());
            // TODO new Did(meta.didDocId); // ultimate test

        } catch (Exception e) {
            fail(e);
        }

        assertNotNull(meta.getLastVersionId());
        assertNotNull(meta.getDateTime());
        // TODO assertEquals(4, meta.lastVersionNumber);
        assertNotNull(meta.getParams());
        assertNotNull(meta.getParams().method);
        assertNotNull(meta.getParams().scid);
        assertNotNull(meta.getParams().updateKeys);
        assertFalse(meta.getParams().updateKeys.isEmpty());
        assertEquals(1, meta.getParams().updateKeys.size());
    }
}
