package ch.admin.bj.swiyu.didtoolbox.cli.jcommander.validator;

import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.CommandParameterNames;
import ch.admin.bj.swiyu.didtoolbox.did.AbstractUtilTestBase;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogDeactivatorContext;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogDeactivatorStrategyException;
import ch.admin.bj.swiyu.didtoolbox.did.model.DidMethodEnum;
import com.beust.jcommander.ParameterException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class DidLogFileParameterValidatorTest extends AbstractUtilTestBase {

    private static final String PARAM_NAME = CommandParameterNames.PARAM_NAME_LONG_DID_LOG_FILE;

    private final DidLogFileParameterValidator validator = new DidLogFileParameterValidator();

    @TempDir
    Path tmpDir;

    private Path writeDidLogFile(String content) throws IOException {
        return Files.writeString(tmpDir.resolve("did.jsonl"), content);
    }

    private void assertRejected(Path didLogFile, String expectedMessageFragment) {
        var exc = assertThrowsExactly(ParameterException.class, () -> validator.validate(PARAM_NAME, didLogFile.toString())); // MUT
        assertTrue(exc.getMessage().startsWith("Parameter " + PARAM_NAME + " should be a regular file containing a valid DID log"), exc.getMessage());
        assertTrue(exc.getMessage().contains(expectedMessageFragment), exc.getMessage());
    }

    private static String deactivate(String didLog, DidMethodEnum didMethod) throws DidLogDeactivatorStrategyException {
        return didLog + System.lineSeparator()
                + DidLogDeactivatorContext.builder(didMethod, TEST_CRYPTO_SUITE_JKS).build().deactivate(didLog);
    }

    @Test
    void validate_validTdwDidLog_accepted() throws IOException {
        var didLogFile = writeDidLogFile(buildInitialTdwDidLogEntry(TEST_CRYPTO_SUITE_JKS));

        assertDoesNotThrow(() -> validator.validate(PARAM_NAME, didLogFile.toString())); // MUT
    }

    @Test
    void validate_zeroLengthFile_rejected() throws IOException {
        var didLogFile = writeDidLogFile("");

        assertRejected(didLogFile, "(found " + didLogFile + ")");
    }

    @Test
    void validate_unparsableContent_rejected() throws IOException {
        assertRejected(writeDidLogFile("this is not a DID log"), "Malformed");
    }

    static Stream<Arguments> initialDidLogEntries() {
        return Stream.of(
                Arguments.of(DidMethodEnum.TDW_0_3, buildInitialTdwDidLogEntry(TEST_CRYPTO_SUITE_JKS)),
                Arguments.of(DidMethodEnum.WEBVH_1_0, buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE_JKS)));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("initialDidLogEntries")
    void validate_deactivatedDidLog_rejected(DidMethodEnum didMethod, String initialDidLogEntry) throws Exception {
        var didLog = deactivate(initialDidLogEntry, didMethod);

        assertRejected(writeDidLogFile(didLog), "deactivated");
    }

    @Test
    void validate_nonUtf8File_rejected() throws IOException {
        var didLogFile = Files.write(tmpDir.resolve("did.jsonl"), new byte[]{(byte) 0xC3, (byte) 0x28});

        assertRejected(didLogFile, "Input length");
    }
}
