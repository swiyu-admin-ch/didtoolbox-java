package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.eid.didresolver.Did;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.FileInputStream;
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

    final private static String ISO_DATE_TIME;
    final private static VerificationMethodKeyProvider VERIFICATION_METHOD_KEY_PROVIDER;

    static {
        ISO_DATE_TIME = "2012-12-12T12:12:12Z";

        try {
            //VERIFICATION_METHOD_KEY_PROVIDER = new Ed25519VerificationMethodKeyProviderImpl(new File("src/test/data/private.pem"), new File("src/test/data/public.pem"));
            VERIFICATION_METHOD_KEY_PROVIDER = new Ed25519VerificationMethodKeyProviderImpl(new FileInputStream("src/test/data/mykeystore.jks"), "changeit", "myalias");
        } catch (Exception intolerable) {
            throw new RuntimeException(intolerable);
        }
    }

    private static Collection<String> invalidDidLogEntries() throws URISyntaxException, MalformedURLException {
        return Arrays.asList(
                "[]", // Should cause "Malformed DID log entry" ("Expected at 5 DID log entry elements but got 0")
                "[\"\",\"\",{},{},[{}]]", // Should cause "Every versionId MUST be a dash-separated combination of version number and entry hash, found: ..."
                "[\"\",\"\",{},,[{}]]",   // Should cause "Malformed DID log entry"
                "[\"\",\"\",,{},[{}]]",   // Should cause "Malformed DID log entry"
                "[\"1-xyz\",\"\",{},{\"\":{}},[{}]]", // Should cause "The versionTime MUST be a valid ISO8601 date/time string"
                "[\"1-xyz\",\"2012-12-12T12:12:12Z\",{},{\"\":{}},[{}]]", // Should cause "DID doc ID is missing"
                "[\"1-xyz\",\"2012-12-12T12:12:12Z\",{\"updateKeys\":{}},{},[{}]]", // Should cause "Malformed DID log entry"
                "[\"1-xyz\",\"2012-12-12T12:12:12Z\",{\"updateKeys\":[{}]},{},[{}]]", // Should cause "Malformed DID log entry"
                "[\"1-xyz\",\"2012-12-12T12:12:12Z\",{},{\"value\":{}},[{}]]", // Should cause "DID doc ID is missing"
                "[\"1-xyz\",\"2012-12-12T12:12:12Z\",{},{\"value\":{\"id\":\"tdw:did:...\"}},]" // Should cause "Malformed DID log entry" ("Proof is missing")
                //"[\"1-xyz\",\"2012-12-12T12:12:12Z\",{\"updateKeys\":[\"xyz\"]},{\"value\":{\"id\":\"tdw:did:...\"}},[{}]]" // Should cause "Malformed DID log entry"
        );
    }

    private static String buildInitialDidLogEntry() {
        try {
            return TdwCreator.builder()
                    .verificationMethodKeyProvider(VERIFICATION_METHOD_KEY_PROVIDER)
                    .assertionMethodKeys(Map.of("my-assert-key-01", JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/assert-key-01.pub"), "my-assert-key-01")))
                    .authenticationKeys(Map.of("my-auth-key-01", JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/auth-key-01.pub"), "my-auth-key-01")))
                    .build()
                    .create(URL.of(new URI("https://127.0.0.1:54858"), null), ZonedDateTime.parse("2012-12-12T12:12:12Z"));
        } catch (Exception intolerable) {
            throw new RuntimeException(intolerable);
        }
    }

    private static String buildDidLog() {

        var initialDidLogEntry = buildInitialDidLogEntry();

        String nextLogEntry = null;
        StringBuilder updatedDidLog = null;
        try {
            updatedDidLog = new StringBuilder(initialDidLogEntry);
            for (int i = 2; i < 5; i++) { // update DID log by adding several new entries

                nextLogEntry = TdwUpdater.builder()
                        .verificationMethodKeyProvider(VERIFICATION_METHOD_KEY_PROVIDER)
                        .assertionMethodKeys(Map.of("my-assert-key-0" + i, JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/assert-key-01.pub"), "my-assert-key-0" + i)))
                        .authenticationKeys(Map.of("my-auth-key-0" + i, JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/auth-key-01.pub"), "my-auth-key-0" + i)))
                        .build()
                        // The versionTime for each log entry MUST be greater than the previous entry’s time.
                        // The versionTime of the last entry MUST be earlier than the current time.
                        .update(updatedDidLog.toString(), ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(i - 1));

                updatedDidLog.append(System.lineSeparator()).append(nextLogEntry);
            }

        } catch (Exception e) {
            fail(e);
        }

        return updatedDidLog.toString();
    }

    @DisplayName("Peeking (into invalid TDW log entry) for various invalidDidLogEntry variants")
    @ParameterizedTest(name = "For invalidDidLogEntry: {0}")
    @MethodSource("invalidDidLogEntries")
    void testThrowsDidLogMetaPeekerException(String invalidDidLogEntry) {

        assertThrowsExactly(DidLogMetaPeekerException.class, () -> {
            DidLogMetaPeeker.peek(invalidDidLogEntry);
        });
    }

    @Test
    void testPeek() {

        DidLogMetaPeeker.DidLogMeta meta = null;
        try {
            meta = DidLogMetaPeeker.peek(buildDidLog()); // MUT
            assertNotNull(meta);
            assertNotNull(meta.didDocId);
            new Did(meta.didDocId); // ultimate test

        } catch (Exception e) {
            fail(e);
        }

        assertNotNull(meta.lastVersionId);
        assertNotNull(meta.dateTime);
        assertEquals(4, meta.lastVersionNumber);
        assertNotNull(meta.params);
        assertNotNull(meta.params.method);
        assertNotNull(meta.params.scid);
        assertNotNull(meta.params.updateKeys);
        assertFalse(meta.params.updateKeys.isEmpty());
        assertEquals(1, meta.params.updateKeys.size());
    }
}
