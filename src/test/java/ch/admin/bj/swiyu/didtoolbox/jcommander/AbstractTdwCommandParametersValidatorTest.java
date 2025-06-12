package ch.admin.bj.swiyu.didtoolbox.jcommander;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.io.File;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

abstract class AbstractTdwCommandParametersValidatorTest {

    protected static final String CREDENTIALS_FILE_PATH = "src/test/data/com.securosys.primus.jce.credentials.properties";

    protected static File dummyDidLogFile = null;

    static {
        try {
            dummyDidLogFile = File.createTempFile("my-did", ".jsonl");
        } catch (IOException e) {
            fail(e);
        }
        dummyDidLogFile.deleteOnExit();
    }

    protected abstract JCommander buildCommandParser();

    protected abstract String[] appendToRequiredCommandArgs(String... args);

    protected void assertAmbiguousParameters() {

        var ambiguousParams = new String[][]{ // perhaps using HashSet<String[]> instead?
                {
                        CommandParameterNames.PARAM_NAME_LONG_SIGNING_KEY_FILE, dummyDidLogFile.getPath(),
                        CommandParameterNames.PARAM_NAME_LONG_JKS_FILE, dummyDidLogFile.getPath()
                },
                {
                        CommandParameterNames.PARAM_NAME_SHORT_SIGNING_KEY_FILE, dummyDidLogFile.getPath(),
                        CommandParameterNames.PARAM_NAME_LONG_JKS_FILE, dummyDidLogFile.getPath()
                },
                {
                        CommandParameterNames.PARAM_NAME_SHORT_SIGNING_KEY_FILE, dummyDidLogFile.getPath(),
                        CommandParameterNames.PARAM_NAME_SHORT_JKS_FILE, dummyDidLogFile.getPath()
                },
                {
                        CommandParameterNames.PARAM_NAME_LONG_SIGNING_KEY_FILE, dummyDidLogFile.getPath(),
                        CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, "whatever"
                },
                {
                        CommandParameterNames.PARAM_NAME_SHORT_SIGNING_KEY_FILE, dummyDidLogFile.getPath(),
                        CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, "whatever"
                },
                {
                        CommandParameterNames.PARAM_NAME_SHORT_SIGNING_KEY_FILE, dummyDidLogFile.getPath(),
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
                    "Supplied source for the (signing/verifying) keys is ambiguous. Use one of the relevant options to supply keys"
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
                    "parameters are incomplete. Use one of the relevant options to supply missing parameters"
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