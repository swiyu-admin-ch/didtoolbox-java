package ch.admin.bj.swiyu.didtoolbox.jcommander;

import ch.admin.bj.swiyu.didtoolbox.DalekEd25519VerificationMethodKeyProviderImpl;
import ch.admin.bj.swiyu.didtoolbox.JwkUtils;
import ch.admin.bj.swiyu.didtoolbox.VerificationMethodKeyProvider;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorContext;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorStrategyException;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogUpdaterContext;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogUpdaterStrategyException;
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
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

// This will suppress all the PMD warnings in this (test) class
@SuppressWarnings("PMD")
abstract class AbstractCommandParametersValidatorTest {

    protected static final String CREDENTIALS_FILE_PATH = "src/test/data/com.securosys.primus.jce.credentials.properties";

    protected static File dummyDidLogFile = null;

    protected static final File somePrivatePEMFile = new File("src/test/data/private.pem");
    protected static final File somePublicPEMFile = new File("src/test/data/public.pem");

    // Total 3 (PrivateKeyEntry) entries available in the JKS: myalias/myalias2/myalias3
    final protected static VerificationMethodKeyProvider TEST_VERIFICATION_METHOD_KEY_PROVIDER;
    final protected static Map<String, String> TEST_ASSERTION_METHOD_KEYS;
    final protected static Map<String, String> TEST_AUTHENTICATION_METHOD_KEYS;

    static {
        try {
            // Total 3 (PrivateKeyEntry) entries available in the JKS: myalias/myalias2/myalias3
            TEST_VERIFICATION_METHOD_KEY_PROVIDER = new DalekEd25519VerificationMethodKeyProviderImpl(new File("src/test/data/private.pem"));
            TEST_ASSERTION_METHOD_KEYS = Map.of("my-assert-key-01", JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/assert-key-01.pub"), "my-assert-key-01"));
            TEST_AUTHENTICATION_METHOD_KEYS = Map.of("my-auth-key-01", JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/auth-key-01.pub"), "my-auth-key-01"));
        } catch (Exception intolerable) {
            throw new IllegalArgumentException(intolerable);
        }
    }

    static {
        try {
            dummyDidLogFile = File.createTempFile("my-did", ".jsonl");

            var initialDidLogEntry = DidLogCreatorContext.builder()
                    .verificationMethodKeyProvider(TEST_VERIFICATION_METHOD_KEY_PROVIDER)
                    .assertionMethodKeys(TEST_ASSERTION_METHOD_KEYS)
                    .authenticationKeys(TEST_AUTHENTICATION_METHOD_KEYS)
                    //.updateKeys(Set.of(new File("src/test/data/public.pem")))
                    .forceOverwrite(true)
                    .build()
                    .create(URL.of(new URI("https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/18fa7c77-9dd1-4e20-a147-fb1bec146085"), null));

            var updatedDidLog = new StringBuilder(initialDidLogEntry)
                    .append(System.lineSeparator())
                    .append(DidLogUpdaterContext.builder()
                            .verificationMethodKeyProvider(TEST_VERIFICATION_METHOD_KEY_PROVIDER)
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

    // CAUTION For calling this function,
    //         see the related instructions in pom.xml in regard to Securosys Primus HSM (JCE security provider)
    private void assertPrimusParameters() {

        assertDoesNotThrow(() -> {
            buildCommandParser().parse(appendToRequiredCommandArgs(
                    CommandParameterNames.PARAM_NAME_LONG_PRIMUS_CREDENTIALS, CREDENTIALS_FILE_PATH,
                    CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, "whatever"
                    //,CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD, "whatever"
            ));
        });

        assertDoesNotThrow(() -> {
            buildCommandParser().parse(appendToRequiredCommandArgs(
                    CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_CREDENTIALS, CREDENTIALS_FILE_PATH,
                    CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS, "whatever"
            ));
        });

        assertDoesNotThrow(() -> {
            buildCommandParser().parse(appendToRequiredCommandArgs(
                    CommandParameterNames.PARAM_NAME_LONG_PRIMUS_CREDENTIALS, CREDENTIALS_FILE_PATH,
                    CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS, "whatever"
            ));
        });

        assertDoesNotThrow(() -> {
            buildCommandParser().parse(appendToRequiredCommandArgs(
                    CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_CREDENTIALS, CREDENTIALS_FILE_PATH,
                    CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, "whatever"
            ));
        });

        // No PARAM_NAME_*_PRIMUS_KEYSTORE_ALIAS
        // No PARAM_NAME_*_PRIMUS_KEYSTORE_PASSWORD

        assertTdwCommandThrowsParameterException(
                CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_CREDENTIALS, CREDENTIALS_FILE_PATH
        );

        assertTdwCommandThrowsParameterException(
                CommandParameterNames.PARAM_NAME_LONG_PRIMUS_CREDENTIALS, CREDENTIALS_FILE_PATH
        );

        // No PARAM_NAME_*_PRIMUS_CREDENTIALS
        // No PARAM_NAME_*_PRIMUS_KEYSTORE_PASSWORD

        /*
        assertTdwCommandThrowsParameterException(
                CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS, "whatever"
        );

        assertTdwCommandThrowsParameterException(
                CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, "whatever"
        );
        */

        // No PARAM_NAME_*_PRIMUS_CREDENTIALS
        // No PARAM_NAME_*_PRIMUS_KEYSTORE_ALIAS

        assertTdwCommandThrowsParameterException(
                CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD, "whatever"
        );

        // No PARAM_NAME_*_PRIMUS_KEYSTORE_PASSWORD

        /*
        assertTdwCommandThrowsParameterException(
                CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE, CREDENTIALS_FILE_PATH,
                CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS, "whatever"
        );

        assertTdwCommandThrowsParameterException(
                CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE, CREDENTIALS_FILE_PATH,
                CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, "whatever"
        );
         */

        // No PARAM_NAME_*_PRIMUS_KEYSTORE_ALIAS

        assertTdwCommandThrowsParameterException(
                CommandParameterNames.PARAM_NAME_LONG_PRIMUS_CREDENTIALS, CREDENTIALS_FILE_PATH,
                CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD, "whatever"
        );

        // No PARAM_NAME_*_PRIMUS_CREDENTIALS

        /*
        assertTdwCommandThrowsParameterException(
                CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS, "whatever",
                CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_PASSWORD, "whatever"
        );

        assertTdwCommandThrowsParameterException(
                CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, "whatever",
                CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD, "whatever"
        );
         */
    }

    protected void assertTdwCommandThrowsParameterException(String... args) {
        assertThrowsParameterException(() -> buildCommandParser().parse(appendToRequiredCommandArgs(args)),
                "Incomplete Primus parameters supplied"
        );
    }

    protected static void assertThrowsParameterException(Executable executable, String containedInErrorMessage) {
        var exc = assertThrowsExactly(ParameterException.class, executable, "Expected: " + containedInErrorMessage);
        if (containedInErrorMessage != null) {
            assertTrue(exc.getMessage().contains(containedInErrorMessage));
        }
    }

    @Test
    void testAbstractValidate() {
        // CAUTION For calling this function,
        //         see the related instructions in pom.xml in regard to Securosys Primus HSM (JCE security provider)
        //assertPrimusParameters();

        assertAmbiguousParameters();
        assertBoundParameters();
    }
}