package ch.admin.bj.swiyu.didtoolbox.cli.jcommander.validator;

import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.CommandParameterNames;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogCreatorContext;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogCreatorStrategyException;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogUpdaterContext;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogUpdaterStrategyException;
import ch.admin.bj.swiyu.didtoolbox.did.model.DidMethodEnum;
import ch.admin.bj.swiyu.didtoolbox.did.model.VerificationMethod;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

// This will suppress all the PMD warnings in this (test) class
@SuppressWarnings("PMD")
abstract class AbstractCommandParametersValidatorTest {

    public static final String TEST_DATA_PATH_PREFIX = "src/test/data/";

    protected static File dummyDidLogFile = null;

    protected static final File somePrivatePEMFile = new File("src/test/data/private.pem");
    protected static final File somePublicPEMFile = new File("src/test/data/public.pem");

    // Total 3 (PrivateKeyEntry) entries available in the JKS: myalias/myalias2/myalias3
    final protected static VcDataIntegrityCryptographicSuite TEST_CRYPTO_SUITE;
    final protected static Set<VerificationMethod> TEST_ASSERTION_METHODS;
    final protected static Set<VerificationMethod> TEST_AUTHENTICATIONS;

    static {
        try {
            // Total 3 (PrivateKeyEntry) entries available in the JKS: myalias/myalias2/myalias3
            TEST_CRYPTO_SUITE = new EdDsaJcs2022VcDataIntegrityCryptographicSuite(Path.of("src/test/data/private.pem"));
            TEST_ASSERTION_METHODS = Set.of(VerificationMethod.ofPEMPath("my-assert-key-01", Path.of(TEST_DATA_PATH_PREFIX + "assert-key-01.pub")));
            TEST_AUTHENTICATIONS = Set.of(VerificationMethod.ofPEMPath("my-auth-key-01", Path.of(TEST_DATA_PATH_PREFIX + "auth-key-01.pub")));

        } catch (Exception intolerable) {
            throw new IllegalArgumentException(intolerable);
        }
    }

    static {
        try {
            dummyDidLogFile = File.createTempFile("my-did", ".jsonl");

            var initialDidLogEntry = DidLogCreatorContext.builder(DidMethodEnum.WEBVH_1_0, TEST_CRYPTO_SUITE)
                    .assertionMethods(TEST_ASSERTION_METHODS)
                    .authentications(TEST_AUTHENTICATIONS)
                    //.updateKeys(Set.of(new File("src/test/data/public.pem")))
                    .build()
                    .create(URL.of(new URI("https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/18fa7c77-9dd1-4e20-a147-fb1bec146085"), null));

            var updatedDidLog = new StringBuilder(initialDidLogEntry)
                    .append(System.lineSeparator())
                    .append(DidLogUpdaterContext.builder(DidMethodEnum.WEBVH_1_0, TEST_CRYPTO_SUITE)
                            .assertionMethods(TEST_ASSERTION_METHODS)
                            .authentications(TEST_AUTHENTICATIONS)
                            //.updateKeys(Set.of(new File("src/test/data/public.pem")))
                            .build()
                            .update(initialDidLogEntry));

            Files.writeString(dummyDidLogFile.toPath(), updatedDidLog);

        } catch (IOException | URISyntaxException | DidLogCreatorStrategyException | DidLogUpdaterStrategyException e) {
            fail(e);
        }
        dummyDidLogFile.deleteOnExit();
    }

    protected abstract JCommander buildCommandParser();

    protected abstract String[] appendToRequiredCommandArgs(String... args);

    protected void assertAmbiguousParameters() {

        var ambiguousParams = new String[][]{ // perhaps using HashSet<String[]> instead?
                {
                        CommandParameterNames.PARAM_NAME_LONG_SIGNING_KEY_FILE, somePrivatePEMFile.getPath(),
                        CommandParameterNames.PARAM_NAME_LONG_JKS_FILE, dummyDidLogFile.getPath()
                },
                {
                        CommandParameterNames.PARAM_NAME_SHORT_SIGNING_KEY_FILE, somePrivatePEMFile.getPath(),
                        CommandParameterNames.PARAM_NAME_LONG_JKS_FILE, dummyDidLogFile.getPath()
                },
                {
                        CommandParameterNames.PARAM_NAME_SHORT_SIGNING_KEY_FILE, somePrivatePEMFile.getPath(),
                        CommandParameterNames.PARAM_NAME_SHORT_JKS_FILE, dummyDidLogFile.getPath()
                },
                {
                        CommandParameterNames.PARAM_NAME_LONG_SIGNING_KEY_FILE, somePrivatePEMFile.getPath(),
                        CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, "whatever"
                },
                {
                        CommandParameterNames.PARAM_NAME_SHORT_SIGNING_KEY_FILE, somePrivatePEMFile.getPath(),
                        CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, "whatever"
                },
                {
                        CommandParameterNames.PARAM_NAME_SHORT_SIGNING_KEY_FILE, somePrivatePEMFile.getPath(),
                        CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS, "whatever"
                },
                {
                        CommandParameterNames.PARAM_NAME_LONG_JKS_FILE, dummyDidLogFile.getPath(),
                        CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, "whatever",
                },
                {
                        CommandParameterNames.PARAM_NAME_SHORT_JKS_FILE, dummyDidLogFile.getPath(),
                        CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, "whatever",
                },
                {
                        CommandParameterNames.PARAM_NAME_SHORT_JKS_FILE, dummyDidLogFile.getPath(),
                        CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS, "whatever",
                }
        };

        for (var params : ambiguousParams) {
            assertThrowsParameterException(() -> buildCommandParser().parse(appendToRequiredCommandArgs(params)),
                    "The supplied sources of (signing/verifying) keys are ambiguous. Use one of the relevant options to supply keys"
            );
        }
    }

    protected void assertBoundParameters() {

        var incompleteBoundParams = new String[][]{ // perhaps using HashSet<String[]> instead?
                {
                        CommandParameterNames.PARAM_NAME_LONG_JKS_FILE, dummyDidLogFile.getPath()
                },
                {
                        CommandParameterNames.PARAM_NAME_SHORT_JKS_FILE, dummyDidLogFile.getPath()
                },
                {
                        CommandParameterNames.PARAM_NAME_LONG_JKS_FILE, dummyDidLogFile.getPath(),
                        CommandParameterNames.PARAM_NAME_LONG_JKS_PASSWORD, "whatever"
                },
                {
                        CommandParameterNames.PARAM_NAME_SHORT_JKS_FILE, dummyDidLogFile.getPath(),
                        CommandParameterNames.PARAM_NAME_LONG_JKS_PASSWORD, "whatever"
                },
                {
                        CommandParameterNames.PARAM_NAME_LONG_JKS_ALIAS, "whatever"
                },
                {
                        CommandParameterNames.PARAM_NAME_LONG_JKS_ALIAS, "whatever"
                },
                {
                        CommandParameterNames.PARAM_NAME_LONG_JKS_PASSWORD, "whatever"
                },
                {
                        CommandParameterNames.PARAM_NAME_LONG_JKS_ALIAS, "whatever",
                        CommandParameterNames.PARAM_NAME_LONG_JKS_PASSWORD, "whatever"
                }, // Primus params
                {
                        CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, "whatever"
                },
                {
                        CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS, "whatever"
                },
                {
                        CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD, "whatever"
                },
                {
                        CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, "whatever",
                        CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD, "whatever"
                },
                {
                        CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS, "whatever",
                        CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD, "whatever"
                },
                {
                        CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS, "whatever",
                        CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD, "whatever"
                }
        };

        for (var params : incompleteBoundParams) {
            assertThrowsParameterException(() -> buildCommandParser().parse(appendToRequiredCommandArgs(params)),
                    "parameter(s) are incomplete. Use one of the relevant options to supply missing parameters"
            );
        }

        var completeBoundParams = new String[][]{ // perhaps using HashSet<String[]> instead?
                {
                        CommandParameterNames.PARAM_NAME_LONG_JKS_FILE, dummyDidLogFile.getPath(),
                        CommandParameterNames.PARAM_NAME_LONG_JKS_ALIAS, "whatever"
                },
                {
                        CommandParameterNames.PARAM_NAME_SHORT_JKS_FILE, dummyDidLogFile.getPath(),
                        CommandParameterNames.PARAM_NAME_LONG_JKS_ALIAS, "whatever"
                },
        };

        for (var params : completeBoundParams) {
            assertDoesNotThrow(() -> buildCommandParser().parse(appendToRequiredCommandArgs(params)));
        }
    }

    protected static void assertThrowsParameterException(Executable executable, String containedInErrorMessage) {
        var exc = assertThrowsExactly(ParameterException.class, executable, "Expected: " + containedInErrorMessage);
        if (containedInErrorMessage != null) {
            assertTrue(exc.getMessage().contains(containedInErrorMessage));
        }
    }

    @Test
    void testAbstractValidate() {
        assertAmbiguousParameters();
        assertBoundParameters();
    }
}