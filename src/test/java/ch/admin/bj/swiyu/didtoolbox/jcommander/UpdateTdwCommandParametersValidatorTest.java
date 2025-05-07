package ch.admin.bj.swiyu.didtoolbox.jcommander;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class UpdateTdwCommandParametersValidatorTest {

    private static final String CREDENTIALS_FILE_PATH = "src/test/data/com.securosys.primus.jce.credentials.properties";

    private static File dummyDidLogFile = null;

    static {
        try {
            dummyDidLogFile = File.createTempFile("mytdwlog", ".jsonl");
        } catch (IOException e) {
            fail(e);
        }
        dummyDidLogFile.deleteOnExit();
    }

    private static JCommander buildUpdateCommand() {
        return JCommander.newBuilder()
                .addCommand("update", new UpdateTdwCommand())
                .build();
    }

    // CAUTION For calling this function,
    //         see the related instructions in pom.xml in regard to Securosys Primus HSM (JCE security provider)
    private static void testValidatePrimusParameters() {

        assertDoesNotThrow(() -> {
            buildUpdateCommand().parse("update", "-d", dummyDidLogFile.getPath(), // required
                    CommandParameterNames.PARAM_NAME_LONG_PRIMUS_CREDENTIALS, CREDENTIALS_FILE_PATH,
                    CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, "whatever"
                    //,CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD, "whatever"
            );
        });

        assertDoesNotThrow(() -> {
            buildUpdateCommand().parse("update", "-d", dummyDidLogFile.getPath(), // required
                    CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_CREDENTIALS, CREDENTIALS_FILE_PATH,
                    CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS, "whatever"
            );
        });

        assertDoesNotThrow(() -> {
            buildUpdateCommand().parse("update", "-d", dummyDidLogFile.getPath(), // required
                    CommandParameterNames.PARAM_NAME_LONG_PRIMUS_CREDENTIALS, CREDENTIALS_FILE_PATH,
                    CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS, "whatever"
            );
        });

        assertDoesNotThrow(() -> {
            buildUpdateCommand().parse("update", "-d", dummyDidLogFile.getPath(), // required
                    CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_CREDENTIALS, CREDENTIALS_FILE_PATH,
                    CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, "whatever"
            );
        });

        // No PARAM_NAME_*_PRIMUS_KEYSTORE_ALIAS
        // No PARAM_NAME_*_PRIMUS_KEYSTORE_PASSWORD

        assertCreateTdwCommandThrowsParameterException(
                CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_CREDENTIALS, CREDENTIALS_FILE_PATH
        );

        assertCreateTdwCommandThrowsParameterException(
                CommandParameterNames.PARAM_NAME_LONG_PRIMUS_CREDENTIALS, CREDENTIALS_FILE_PATH
        );

        // No PARAM_NAME_*_PRIMUS_CREDENTIALS
        // No PARAM_NAME_*_PRIMUS_KEYSTORE_PASSWORD

        /*
        assertCreateTdwCommandThrowsParameterException(
                CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS, "whatever"
        );

        assertCreateTdwCommandThrowsParameterException(
                CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, "whatever"
        );
        */

        // No PARAM_NAME_*_PRIMUS_CREDENTIALS
        // No PARAM_NAME_*_PRIMUS_KEYSTORE_ALIAS

        assertCreateTdwCommandThrowsParameterException(
                CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD, "whatever"
        );

        // No PARAM_NAME_*_PRIMUS_KEYSTORE_PASSWORD

        /*
        assertCreateTdwCommandThrowsParameterException(
                CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE, CREDENTIALS_FILE_PATH,
                CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS, "whatever"
        );

        assertCreateTdwCommandThrowsParameterException(
                CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE, CREDENTIALS_FILE_PATH,
                CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, "whatever"
        );
         */

        // No PARAM_NAME_*_PRIMUS_KEYSTORE_ALIAS

        assertCreateTdwCommandThrowsParameterException(
                CommandParameterNames.PARAM_NAME_LONG_PRIMUS_CREDENTIALS, CREDENTIALS_FILE_PATH,
                CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD, "whatever"
        );

        // No PARAM_NAME_*_PRIMUS_CREDENTIALS

        /*
        assertCreateTdwCommandThrowsParameterException(
                CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS, "whatever",
                CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_PASSWORD, "whatever"
        );

        assertCreateTdwCommandThrowsParameterException(
                CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, "whatever",
                CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD, "whatever"
        );
         */
    }

    private static void assertCreateTdwCommandThrowsParameterException(String... args) {
        var argz = Stream.concat(
                        Arrays.stream(new String[]{"update", "-d", dummyDidLogFile.getPath()}), // required
                        Arrays.stream(args))
                .toArray(size -> (String[]) Array.newInstance(String.class, size));

        assertThrowsParameterException(() -> buildUpdateCommand().parse(argz),
                "Incomplete Primus parameters supplied"
        );
    }

    private static void assertThrowsParameterException(Executable executable, String containedInErrorMessage) {
        var exc = assertThrowsExactly(ParameterException.class, executable);
        if (containedInErrorMessage != null) {
            assertTrue(exc.getMessage().contains(containedInErrorMessage));
        }
    }

    @Test
    void testValidate() {
        // CAUTION For calling this function,
        //         see the related instructions in pom.xml in regard to Securosys Primus HSM (JCE security provider)
        //testValidatePrimusParameters();
    }
}