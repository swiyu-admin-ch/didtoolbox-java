package ch.admin.bj.swiyu.didtoolbox.jcommander;

import ch.admin.bj.swiyu.didtoolbox.JwkUtils;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorContext;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorStrategyException;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogUpdaterContext;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogUpdaterStrategyException;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Array;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

// This will suppress all the PMD warnings in this (test) class
@SuppressWarnings("PMD")
class VerifyProofOfPossessionCommandParametersValidatorTest { // TODO Extend AbstractCommandParametersValidatorTest class, instead
    protected static File dummyDidLogFile = null;
    protected static final String dummyJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30";

    // Total 3 (PrivateKeyEntry) entries available in the JKS: myalias/myalias2/myalias3
    final private static VcDataIntegrityCryptographicSuite TEST_CRYPTO_SUITE;
    final private static Map<String, String> TEST_ASSERTION_METHOD_KEYS;
    final private static Map<String, String> TEST_AUTHENTICATION_METHOD_KEYS;

    static {
        try {
            // Total 3 (PrivateKeyEntry) entries available in the JKS: myalias/myalias2/myalias3
            TEST_CRYPTO_SUITE = new EdDsaJcs2022VcDataIntegrityCryptographicSuite(Path.of("src/test/data/private.pem"));
            TEST_ASSERTION_METHOD_KEYS = Map.of("my-assert-key-01", JwkUtils.loadECPublicJWKasJSON(Path.of("src/test/data/assert-key-01.pub"), "my-assert-key-01"));
            TEST_AUTHENTICATION_METHOD_KEYS = Map.of("my-auth-key-01", JwkUtils.loadECPublicJWKasJSON(Path.of("src/test/data/auth-key-01.pub"), "my-auth-key-01"));
        } catch (Exception intolerable) {
            throw new IllegalArgumentException(intolerable);
        }
    }

    static {
        try {
            dummyDidLogFile = File.createTempFile("my-did", ".jsonl");

            var initialDidLogEntry = DidLogCreatorContext.builder()
                    .cryptographicSuite(TEST_CRYPTO_SUITE)
                    .assertionMethodKeys(TEST_ASSERTION_METHOD_KEYS)
                    .authenticationKeys(TEST_AUTHENTICATION_METHOD_KEYS)
                    .build()
                    .create(URL.of(new URI("https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/18fa7c77-9dd1-4e20-a147-fb1bec146085"), null));

            var updatedDidLog = new StringBuilder(initialDidLogEntry)
                    .append(System.lineSeparator())
                    .append(DidLogUpdaterContext.builder()
                            .cryptographicSuite(TEST_CRYPTO_SUITE)
                            .assertionMethodKeys(TEST_ASSERTION_METHOD_KEYS)
                            .authenticationKeys(TEST_AUTHENTICATION_METHOD_KEYS)
                            //.updateKeys(Set.of(new File("src/test/data/public.pem")))
                            .build()
                            .update(initialDidLogEntry));

            Files.writeString(dummyDidLogFile.toPath(), updatedDidLog);

        } catch (IOException | URISyntaxException | DidLogCreatorStrategyException | DidLogUpdaterStrategyException e) {
            fail(e);
        }
        dummyDidLogFile.deleteOnExit();
    }

    private JCommander buildCommandParser() {
        return JCommander.newBuilder()
                .addCommand(VerifyProofOfPossessionCommand.COMMAND_NAME, new VerifyProofOfPossessionCommand())
                .build();
    }

    private String[] appendToCommandArgs(String... args) {
        return Stream.concat(
                        Arrays.stream(new String[]{
                                VerifyProofOfPossessionCommand.COMMAND_NAME,
                        }),
                        Arrays.stream(args))
                .toArray(size -> (String[]) Array.newInstance(String.class, size));
    }

    static void assertThrowsParameterException(Executable executable, String containedInErrorMessage) {
        var exc = assertThrowsExactly(ParameterException.class, executable, "Expected: " + containedInErrorMessage);
        if (containedInErrorMessage != null) {
            assertTrue(exc.getMessage().contains(containedInErrorMessage));
        }
    }

    static void assertThrowsParameterException(Executable executable) {
        assertThrowsExactly(ParameterException.class, executable);
    }

    @Test
    void validParamValues() {
        assertDoesNotThrow(() -> buildCommandParser().parse(appendToCommandArgs(
                CommandParameterNames.PARAM_NAME_LONG_DID_LOG_FILE, dummyDidLogFile.getPath(),
                CommandParameterNames.PARAM_NAME_LONG_NONCE, "whatever",
                CommandParameterNames.PARAM_NAME_LONG_JWT, dummyJWT)));
    }

    @Test
    void invalidParamValues() {
        var incompleteParams = new String[][]{
                {
                        CommandParameterNames.PARAM_NAME_LONG_DID_LOG_FILE, "not a file", // invalid value
                        CommandParameterNames.PARAM_NAME_LONG_NONCE, "whatever",
                        CommandParameterNames.PARAM_NAME_LONG_JWT, dummyJWT,
                },
                {
                        CommandParameterNames.PARAM_NAME_LONG_DID_LOG_FILE, dummyDidLogFile.getPath(),
                        CommandParameterNames.PARAM_NAME_LONG_NONCE, "whatever",
                        CommandParameterNames.PARAM_NAME_LONG_JWT, "invalid jwt", // invalid value
                },
        };

        for (var params : incompleteParams) {
            assertThrowsParameterException(() -> buildCommandParser().parse(appendToCommandArgs(params)));
        }
    }

    @Test
    void missingParam() {
        var incompleteParams = new String[][]{
                {
                        CommandParameterNames.PARAM_NAME_LONG_NONCE, "whatever",
                        CommandParameterNames.PARAM_NAME_LONG_JWT, dummyJWT,
                },
                {
                        CommandParameterNames.PARAM_NAME_LONG_DID_LOG_FILE, dummyDidLogFile.getPath(),
                        CommandParameterNames.PARAM_NAME_LONG_JWT, dummyJWT,
                },
                {
                        CommandParameterNames.PARAM_NAME_LONG_DID_LOG_FILE, dummyDidLogFile.getPath(),
                        CommandParameterNames.PARAM_NAME_LONG_NONCE, "whatever",
                },
                {
                        CommandParameterNames.PARAM_NAME_SHORT_NONCE, "whatever",
                        CommandParameterNames.PARAM_NAME_SHORT_JWT, dummyJWT,
                },
                {
                        CommandParameterNames.PARAM_NAME_SHORT_DID_LOG_FILE, dummyDidLogFile.getPath(),
                        CommandParameterNames.PARAM_NAME_SHORT_JWT, dummyJWT,
                },
                {
                        CommandParameterNames.PARAM_NAME_SHORT_DID_LOG_FILE, dummyDidLogFile.getPath(),
                        CommandParameterNames.PARAM_NAME_SHORT_NONCE, "whatever",
                },
                {
                        CommandParameterNames.PARAM_NAME_LONG_NONCE, "whatever",
                        CommandParameterNames.PARAM_NAME_SHORT_JWT, dummyJWT,
                },
                {
                        CommandParameterNames.PARAM_NAME_LONG_DID_LOG_FILE, dummyDidLogFile.getPath(),
                        CommandParameterNames.PARAM_NAME_SHORT_JWT, dummyJWT,
                },
                {
                        CommandParameterNames.PARAM_NAME_LONG_DID_LOG_FILE, dummyDidLogFile.getPath(),
                        CommandParameterNames.PARAM_NAME_SHORT_NONCE, "whatever",
                },
                {
                        CommandParameterNames.PARAM_NAME_SHORT_NONCE, "whatever",
                        CommandParameterNames.PARAM_NAME_LONG_JWT, dummyJWT,
                },
                {
                        CommandParameterNames.PARAM_NAME_SHORT_DID_LOG_FILE, dummyDidLogFile.getPath(),
                        CommandParameterNames.PARAM_NAME_LONG_JWT, dummyJWT,
                },
                {
                        CommandParameterNames.PARAM_NAME_SHORT_DID_LOG_FILE, dummyDidLogFile.getPath(),
                        CommandParameterNames.PARAM_NAME_LONG_NONCE, "whatever",
                },
        };

        for (var params : incompleteParams) {
            assertThrowsParameterException(() -> buildCommandParser().parse(appendToCommandArgs(params)),
                    "The following option is required:");
        }
    }

}
