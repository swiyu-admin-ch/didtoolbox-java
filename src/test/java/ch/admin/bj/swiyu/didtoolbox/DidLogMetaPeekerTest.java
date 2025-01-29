package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.eid.didresolver.Did;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class DidLogMetaPeekerTest {

    private static Collection<String> invalidDidLogEntries() throws URISyntaxException, MalformedURLException {
        return Arrays.asList(
                "[\"\",\"\",{},{},[{}]]", // Should cause "Every versionId MUST be a dash-separated combination of version number and entry hash, found: ..."
                "[\"\",\"\",{},,[{}]]",   // Should cause "Malformed DID log entry"
                "[\"\",\"\",,{},[{}]]",   // Should cause "Malformed DID log entry"
                "[\"1-xyz\",\"\",{},{\"\":{}},[{}]]", // Should cause "The versionTime MUST be a valid ISO8601 date/time string"
                "[\"1-xyz\",\"2012-12-12T12:12:12Z\",{},{\"\":{}},[{}]]", // Should cause "DID doc ID is missing"
                "[\"1-xyz\",\"2012-12-12T12:12:12Z\",{},{\"value\":{}},[{}]]", // Should cause "DID doc ID is missing"
                "[\"1-xyz\",\"2012-12-12T12:12:12Z\",{},{\"value\":{\"id\":\"tdw:did:...\"}},]" // Should cause "Malformed DID log entry"
        );
    }

    private static String buildInitialDidLogEntry() {
        try {
            return TdwCreator.builder()
                    .verificationMethodKeyProvider(new Ed25519VerificationMethodKeyProviderImpl(new File("src/test/data/private.pem"), new File("src/test/data/public.pem")))
                    .assertionMethodKeys(Map.of("my-assert-key-01", JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/assert-key-01.pub"), "my-assert-key-01")))
                    .authenticationKeys(Map.of("my-auth-key-01", JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/auth-key-01.pub"), "my-auth-key-01")))
                    .build()
                    .create(URL.of(new URI("https://127.0.0.1:54858"), null), ZonedDateTime.parse("2012-12-12T12:12:12Z"));
        } catch (Exception intolerable) {
            throw new RuntimeException(intolerable);
        }
    }

    @DisplayName("Peeking (into invalid TDW log entry) for various invalidDidLogEntry variants")
    @ParameterizedTest(name = "For invalidDidLogEntry: {0}")
    @MethodSource("invalidDidLogEntries")
    void testThrowsDidLogMetaPeekerException(String invalidDidLogEntry) {

        assertThrowsExactly(DidLogMetaPeekerException.class, () -> {
            var didTDW = DidLogMetaPeeker.peek(invalidDidLogEntry);
        });
    }

    @Test
    void testPeek() {

        var initialDidLogEntry = buildInitialDidLogEntry();

        DidLogMetaPeeker.DidLogMeta meta = null;
        try {
            meta = DidLogMetaPeeker.peek(initialDidLogEntry); // MUT
            assertNotNull(meta);
            assertNotNull(meta.didDocId);
            new Did(meta.didDocId); // ultimate test

        } catch (Exception e) {
            fail(e);
        }

        assertNotNull(meta.lastVersionId);
        assertNotNull(meta.dateTime);
        assertEquals(1, meta.lastVersionNumber);
        assertNotNull(meta.params);
        assertNotNull(meta.params.method);
        assertNotNull(meta.params.scid);
        assertNotNull(meta.params.updateKeys);
        assertFalse(meta.params.updateKeys.isEmpty());
        assertEquals(1, meta.params.updateKeys.size());
    }
}
