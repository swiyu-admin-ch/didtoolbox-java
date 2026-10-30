package ch.admin.bj.swiyu.didtoolbox.model;

import ch.admin.bj.swiyu.didtoolbox.did.AbstractUtilTestBase;
import ch.admin.bj.swiyu.didtoolbox.did.DidLogMeta;
import ch.admin.bj.swiyu.didtoolbox.did.DidLogMetaPeekerException;
import ch.admin.bj.swiyu.didtoolbox.did.model.DidMethodEnum;
import ch.admin.bj.swiyu.didtoolbox.did.tdw.MalformedTdwDidLogMetaPeekerException;
import ch.admin.bj.swiyu.didtoolbox.did.tdw.TdwDidLogMetaPeeker;
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
class TdwDidLogMetaPeekerTest extends AbstractUtilTestBase {

    private static Collection<String> malformedDidLogEntries() {
        return Arrays.asList(
                "[]", // Should cause "Malformed DID log entry" ("Expected at 5 DID log entry elements but got 0")
                "[,,,,]",
                "[,\"\",{},{},[{}]]",
                "[\"\",,{},{},[{}]]",
                """
                        ["","",,{},[{}]]
                        ["","",,{},[{}]]
                        """,
                "[\"\",\"\",{},,[{}]]"
                // malformed "DataIntegrityProof" is irrelevant in this context, as it will be verified by resolver afterwards
                //"[\"\",\"\",{},{},]",
                //"[\"\",\"\",{},{},{}]",
                //"[\"\",\"\",{},{},[]]"
        );
    }

    private static Collection<String> invalidDidLogEntries() {
        return Arrays.asList(
                "[\"\",\"\",{},{},[{}]]", // Should cause "Every versionId MUST be a dash-separated combination of version number and entry hash, found: ..."
                "[\"1-xyz\",\"\",{},{\"\":{}},[{}]]", // Should cause "The versionTime MUST be a valid ISO8601 date/time string"
                "[\"1-xyz\",\"2012-12-12T12:12:12Z\",{},{\"\":{}},[{}]]", // Should cause "DID doc ID is missing"
                "[\"1-xyz\",\"2012-12-12T12:12:12Z\",{\"updateKeys\":{}},{},[{}]]", // Should cause "Malformed DID log entry"
                "[\"1-xyz\",\"2012-12-12T12:12:12Z\",{\"updateKeys\":[{}]},{},[{}]]", // Should cause "Malformed DID log entry"
                "[\"1-xyz\",\"2012-12-12T12:12:12Z\",{},{\"value\":{}},[{}]]" // Should cause "DID doc ID is missing"
                //"[\"1-xyz\",\"2012-12-12T12:12:12Z\",{\"updateKeys\":[\"xyz\"]},{\"value\":{\"id\":\"tdw:did:...\"}},[{}]]" // Should cause "Malformed DID log entry"
        );
    }

    @DisplayName("Peeking (into malformed TDW log entry) for various malformedDidLogEntry variants")
    @ParameterizedTest(name = "For malformedDidLogEntry: {0}")
    @MethodSource("malformedDidLogEntries")
    void testThrowsMalformedTdwDidLogMetaPeekerException(String malformedDidLogEntry) {

        assertThrowsExactly(MalformedTdwDidLogMetaPeekerException.class, () -> {
            TdwDidLogMetaPeeker.peek(malformedDidLogEntry);
        });
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

        AtomicReference<DidLogMeta> meta = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            meta.set(TdwDidLogMetaPeeker.peek(buildTdwDidLog(TEST_CRYPTO_SUITE_JKS))); // MUT

            assertNotNull(meta);
            assertNotNull(meta.get().getDidDoc().getId());
            new Did(meta.get().getDidDoc().getId()); // ultimate test
        });

        assertNotNull(meta.get().getLastVersionId());
        assertNotNull(meta.get().getDateTime());
        assertEquals(4, meta.get().getLastVersionNumber());
        assertNotNull(meta.get().getParams());
        assertNotNull(meta.get().getParams().getDidMethodEnum());
        assertEquals(DidMethodEnum.TDW_0_3, meta.get().getParams().getDidMethodEnum());
        assertNotNull(meta.get().getParams().getScid());
        assertNotNull(meta.get().getParams().getUpdateKeys());
        assertFalse(meta.get().getParams().getUpdateKeys().isEmpty());
        assertEquals(1, meta.get().getParams().getUpdateKeys().size());
    }
}
