package ch.admin.bj.swiyu.didtoolbox.model;

import ch.admin.bj.swiyu.didtoolbox.AbstractUtilTestBase;
import ch.admin.eid.didresolver.Did;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Arrays;
import java.util.Collection;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

// This will suppress all the PMD warnings in this (test) class
@SuppressWarnings("PMD")
class WebVhDidLogMetaPeekerTest extends AbstractUtilTestBase {

    private static Collection<Object[]> malformedDidLogEntries() {
        return Arrays.asList(new String[][]{
                        {"[]", "Malformed did:webvh:1.0 log entry"},
                        {"[\"\",\"\",{},{},[{}]]", "Malformed did:webvh:1.0 log entry"}, // did:tdw:0.3 format
                        {"{,,,,}", "Malformed did:webvh:1.0 log entry"},
                        {"{\"versionId\": {}}", "Malformed did:webvh:1.0 log entry"}, // string expected, not object
                        {"{\"versionTime\": {}}", "Malformed did:webvh:1.0 log entry"}, // string expected, not object
                        {"{\"state\": []}", "Malformed did:webvh:1.0 log entry"}, // object expected, not array
                        // malformed "DataIntegrityProof" is irrelevant in this context, as it will be verified by resolver afterwards
                        //{"{\"proof\": {}}", "Malformed did:webvh:1.0 log entry"}, // array expected, not object
                }
        );
    }


    private static Collection<Object[]> invalidDidLogEntries() {
        return Arrays.asList(new String[][]{
                /*
                TODO cover other cases like:
                - "Every versionId MUST be a dash-separated combination of version number and entry hash, found: ..."
                - "The versionTime MUST be a valid ISO8601 date/time string"
                - "DID doc ID is missing"
                 */
                {"""
                        {"versionTime": "2025-04-29T17:15:59Z", "parameters": {"witness": {"threshold": 2, "witnesses": [{"id": "did:key:z6MknJjDn4BuvPrr3nG9GhmdbeiCGT27KJumPXz9i7Q3LobW", "weight": 1}, {"id": "did:key:z6MkvXRkuaGJgDzmRY7XFwUWGt8PccUdHrknR3oUwB42LjS9", "weight": 1}, {"id": "did:key:z6MkhkfmcK42GN8DVNxjyYtAgyn21EsXAowNhUPzmGppcVfS", "weight": 1}]}, "updateKeys": ["z6MkhgLHMevgX5xE69NLJrm1vPFCWRSZfuBgfJPkUAfj8bGZ"], "method": "did:webvh:0.5", "scid": "QmQyDxVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmQyDxVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkhgLHMevgX5xE69NLJrm1vPFCWRSZfuBgfJPkUAfj8bGZ#z6MkhgLHMevgX5xE69NLJrm1vPFCWRSZfuBgfJPkUAfj8bGZ", "created": "2025-04-29T17:15:59Z", "proofPurpose": "assertionMethod", "proofValue": "z4ggCRSgjGoEwaTTGAz7JHz4h1k3Afp8hzDC2DyHe7riEULVriRwHLdf8gA3VR1xXEHxKkz9ikrX25YPYsVtWZMCG"}]}""",
                        "Missing versionId"},
                {"""
                        {"versionId": "1-QmV8pidQB1moYe2AKjNvi2bQghv8Gah18794HrGki1yXQw", "parameters": {"witness": {"threshold": 2, "witnesses": [{"id": "did:key:z6MknJjDn4BuvPrr3nG9GhmdbeiCGT27KJumPXz9i7Q3LobW", "weight": 1}, {"id": "did:key:z6MkvXRkuaGJgDzmRY7XFwUWGt8PccUdHrknR3oUwB42LjS9", "weight": 1}, {"id": "did:key:z6MkhkfmcK42GN8DVNxjyYtAgyn21EsXAowNhUPzmGppcVfS", "weight": 1}]}, "updateKeys": ["z6MkhgLHMevgX5xE69NLJrm1vPFCWRSZfuBgfJPkUAfj8bGZ"], "method": "did:webvh:0.5", "scid": "QmQyDxVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmQyDxVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkhgLHMevgX5xE69NLJrm1vPFCWRSZfuBgfJPkUAfj8bGZ#z6MkhgLHMevgX5xE69NLJrm1vPFCWRSZfuBgfJPkUAfj8bGZ", "created": "2025-04-29T17:15:59Z", "proofPurpose": "assertionMethod", "proofValue": "z4ggCRSgjGoEwaTTGAz7JHz4h1k3Afp8hzDC2DyHe7riEULVriRwHLdf8gA3VR1xXEHxKkz9ikrX25YPYsVtWZMCG"}]}""",
                        "Missing versionTime"},
                {"""
                        {"versionId": "1-QmV8pidQB1moYe2AKjNvi2bQghv8Gah18794HrGki1yXQw", "versionTime": "2025-04-29T17:15:59Z", "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmQyDxVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn:domain.example"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkhgLHMevgX5xE69NLJrm1vPFCWRSZfuBgfJPkUAfj8bGZ#z6MkhgLHMevgX5xE69NLJrm1vPFCWRSZfuBgfJPkUAfj8bGZ", "created": "2025-04-29T17:15:59Z", "proofPurpose": "assertionMethod", "proofValue": "z4ggCRSgjGoEwaTTGAz7JHz4h1k3Afp8hzDC2DyHe7riEULVriRwHLdf8gA3VR1xXEHxKkz9ikrX25YPYsVtWZMCG"}]}""",
                        "the supplied JSON instance is not a valid DID log: \"parameters\" is a required property"},
                {"""
                        {"versionId": "1-QmV8pidQB1moYe2AKjNvi2bQghv8Gah18794HrGki1yXQw", "versionTime": "2025-04-29T17:15:59Z", "parameters": {"witness": {"threshold": 2, "witnesses": [{"id": "did:key:z6MknJjDn4BuvPrr3nG9GhmdbeiCGT27KJumPXz9i7Q3LobW", "weight": 1}, {"id": "did:key:z6MkvXRkuaGJgDzmRY7XFwUWGt8PccUdHrknR3oUwB42LjS9", "weight": 1}, {"id": "did:key:z6MkhkfmcK42GN8DVNxjyYtAgyn21EsXAowNhUPzmGppcVfS", "weight": 1}]}, "updateKeys": ["z6MkhgLHMevgX5xE69NLJrm1vPFCWRSZfuBgfJPkUAfj8bGZ"], "method": "did:webvh:0.5", "scid": "QmQyDxVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn"}, "proof": [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6MkhgLHMevgX5xE69NLJrm1vPFCWRSZfuBgfJPkUAfj8bGZ#z6MkhgLHMevgX5xE69NLJrm1vPFCWRSZfuBgfJPkUAfj8bGZ", "created": "2025-04-29T17:15:59Z", "proofPurpose": "assertionMethod", "proofValue": "z4ggCRSgjGoEwaTTGAz7JHz4h1k3Afp8hzDC2DyHe7riEULVriRwHLdf8gA3VR1xXEHxKkz9ikrX25YPYsVtWZMCG"}]}""",
                        "Missing DID document"}}
        );
    }

    @DisplayName("Peeking (into incompatible did:webvh log entry) for various malformedDidLogEntry variants")
    @ParameterizedTest(name = "Expected exception ''{1}'' thrown for malformedDidLogEntry: {0}")
    @MethodSource("malformedDidLogEntries")
    void testThrowsMalformedWebVerifiableHistoryDidLogMetaPeekerException(String malformedDidLogEntry, String containedInExcMessage) {

        var exc = assertThrowsExactly(MalformedWebVerifiableHistoryDidLogMetaPeekerException.class, () -> {
            WebVerifiableHistoryDidLogMetaPeeker.peek(malformedDidLogEntry);
        });
        assertTrue(exc.getMessage().contains(containedInExcMessage));
    }

    @DisplayName("Peeking (into invalid did:webvh log entry) for various invalidDidLogEntry variants")
    @ParameterizedTest(name = "Expected exception ''{1}'' thrown for invalidDidLogEntry: {0}")
    @MethodSource("invalidDidLogEntries")
    void testThrowsDidLogMetaPeekerException(String invalidDidLogEntry, String containedInExcMessage) {

        var exc = assertThrowsExactly(DidLogMetaPeekerException.class, () -> {
            WebVerifiableHistoryDidLogMetaPeeker.peek(invalidDidLogEntry);
        });
        assertTrue(exc.getMessage().contains(containedInExcMessage));
    }

    @Test
    void testPeek() {

        var meta = new AtomicReference<DidLogMeta>();
        assertDoesNotThrow(() -> {
            meta.set(WebVerifiableHistoryDidLogMetaPeeker.peek("""
                    { "versionId": "1-QmQNjSbRroDtnctDN57Fjvd4e5jYHWVTgMZpzJiTbPfQ5K", "versionTime": "2025-08-06T08:55:01Z", "parameters": { "method": "did:webvh:1.0", "scid": "QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX", "updateKeys": [ "z6MkkkjG6shmZk6D2ghgDbpJQHD4xvpZhzYiWSLKDeznibiJ" ], "portable": false }, "state": { "@context": [ "https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1" ], "id": "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com", "authentication": [ "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com#auth-key-01" ], "assertionMethod": [ "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com#assert-key-01" ], "verificationMethod": [ { "id": "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com#auth-key-01", "type": "JsonWebKey2020", "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "5d-hJaS_UKIU1c05hEBhZa8Xkj_AqBDmqico_PSrRfU", "y": "TK5YKD_osEaVrDBnah-jUDXI27yqFVIo6ZYTfWp-NbY", "kid": "auth-key-01" } }, { "id": "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com#assert-key-01", "type": "JsonWebKey2020", "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "7jWgolr5tQIUIGp9sDaB0clAiXcFwVYXUhEiXXLkmKg", "y": "NYGIxi2VGEv2OL_WqzVOd_VKjOQbl1kaERYbpAjWo58", "kid": "assert-key-01" } } ] }, "proof": [ { "type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "created": "2025-08-13T05:43:17Z", "verificationMethod": "did:key:z6MkkkjG6shmZk6D2ghgDbpJQHD4xvpZhzYiWSLKDeznibiJ#z6MkkkjG6shmZk6D2ghgDbpJQHD4xvpZhzYiWSLKDeznibiJ", "proofPurpose": "assertionMethod", "proofValue": "z3L7j2siRiZ4zziQQmRqLY5qH2RfVz6VTC5gbDE6vntw1De5Ej5DNR3wDU6m9KRiUYPm9o8P89yMzNk5EhWVTo4Tn" } ] }
                    { "versionId": "2-QmYkDQ83oPnBqyUEjdUdZZCc8VjQY7aE5BikRaa8cZAxVS", "versionTime": "2025-08-13T08:46:50Z", "parameters": {}, "state": { "@context": [ "https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1" ], "id": "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com", "authentication": [ "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com#auth-key-01" ], "assertionMethod": [ "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com#assert-key-01" ], "verificationMethod": [ { "id": "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com#auth-key-01", "type": "JsonWebKey2020", "publicKeyJwk": { "kty": "EC", "crv": "P-256", "kid": "auth-key-01", "x": "Ow_aAo2hbAYgEhKAOeu3TYO8bbKOxgJ2gndk46AaXF0", "y": "hdVPThXbmadBl3L5HaYjiz8ewIAve4VHqOgs98MdV5M" } }, { "id": "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com#assert-key-01", "type": "JsonWebKey2020", "publicKeyJwk": { "kty": "EC", "crv": "P-256", "kid": "assert-key-02", "x": "oZq9zqDbbYfRV9gdXbLJaaKWF9G27P4CQfTEyC1aT0I", "y": "QS-uHvmj1mVLB5zJtnwTyWYRZIML4RzvCf4qOrsqfWQ" } } ] }, "proof": [ { "type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "created": "2025-08-13T09:02:55Z", "verificationMethod": "did:key:z6MkkkjG6shmZk6D2ghgDbpJQHD4xvpZhzYiWSLKDeznibiJ#z6MkkkjG6shmZk6D2ghgDbpJQHD4xvpZhzYiWSLKDeznibiJ", "proofPurpose": "assertionMethod", "proofValue": "z2tZe9tFzyTKWRX7NEpf3ARRs7yZqu5Kq8jzr5qzzffeN9FeJPzmKs6Jb1TMNfpn8Nar6WEfifvMT5SVWozJruTwD" } ] }
                    """)); // MUT

            assertNotNull(meta.get());
            assertNotNull(meta.get().getDidDoc().getId());
            new Did(meta.get().getDidDoc().getId()); // ultimate test
        });

        assertNotNull(meta.get().getLastVersionId());
        assertNotNull(meta.get().getDateTime());
        assertEquals(2, meta.get().lastVersionNumber);
        assertNotNull(meta.get().getParams());
        assertNotNull(meta.get().getParams().method);
        assertEquals(DidMethodEnum.WEBVH_1_0, meta.get().getParams().getDidMethodEnum());
        assertNotNull(meta.get().getParams().scid);
        assertNotNull(meta.get().getParams().updateKeys);
        assertFalse(meta.get().getParams().updateKeys.isEmpty());
        assertEquals(1, meta.get().getParams().updateKeys.size());
    }

    @Test
    void testPeekGenerated() {

        var meta = new AtomicReference<DidLogMeta>();
        assertDoesNotThrow(() -> {
            meta.set(WebVerifiableHistoryDidLogMetaPeeker.peek(buildWebVhDidLog(TEST_CRYPTO_SUITE_JKS))); // MUT

            assertNotNull(meta);
            assertNotNull(meta.get().getDidDoc().getId());
            new Did(meta.get().getDidDoc().getId()); // ultimate test
        });

        assertNotNull(meta.get().getLastVersionId());
        assertNotNull(meta.get().getDateTime());
        // CAUTION An expected value depends on buildWebVhDidLog helper
        assertEquals(4, meta.get().lastVersionNumber);
        assertNotNull(meta.get().getParams());
        assertNotNull(meta.get().getParams().method);
        assertNotNull(meta.get().getParams().scid);
        assertNotNull(meta.get().getParams().updateKeys);
        assertFalse(meta.get().getParams().updateKeys.isEmpty());
        assertEquals(1, meta.get().getParams().updateKeys.size());
    }
}
