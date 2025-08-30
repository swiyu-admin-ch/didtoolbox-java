package ch.admin.bj.swiyu.didtoolbox.model;

import ch.admin.bj.swiyu.didtoolbox.AbstractUtilTestBase;
import ch.admin.eid.didresolver.Did;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.jupiter.api.Assertions.*;

class TdwDidLogMetaPeekerTest extends AbstractUtilTestBase {

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

    @DisplayName("Peeking (into invalid TDW log entry) for various invalidDidLogEntry variants")
    @ParameterizedTest(name = "For invalidDidLogEntry: {0}")
    @MethodSource("invalidDidLogEntries")
    void testThrowsDidLogMetaPeekerException(String invalidDidLogEntry) {

        assertThrowsExactly(DidLogMetaPeekerException.class, () -> {
            TdwDidLogMetaPeeker.peek(invalidDidLogEntry);
        });
    }

    @Test
    void testPeek() {

        DidLogMeta meta = null;
        try {
            meta = TdwDidLogMetaPeeker.peek(buildTdwDidLog(TEST_VERIFICATION_METHOD_KEY_PROVIDER_JKS)); // MUT
            assertNotNull(meta);
            assertNotNull(meta.getDidDoc().getId());
            new Did(meta.getDidDoc().getId()); // ultimate test

        } catch (Exception e) {
            fail(e);
        }

        assertNotNull(meta.getLastVersionId());
        assertNotNull(meta.getDateTime());
        assertEquals(4, meta.lastVersionNumber);
        assertNotNull(meta.getParams());
        assertNotNull(meta.getParams().method);
        assertNotNull(meta.getParams().scid);
        assertNotNull(meta.getParams().updateKeys);
        assertFalse(meta.getParams().updateKeys.isEmpty());
        assertEquals(1, meta.getParams().updateKeys.size());
    }
}
