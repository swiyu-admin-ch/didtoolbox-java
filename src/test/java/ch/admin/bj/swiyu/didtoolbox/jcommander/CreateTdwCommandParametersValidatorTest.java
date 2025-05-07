package ch.admin.bj.swiyu.didtoolbox.jcommander;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class CreateTdwCommandParametersValidatorTest {

    private static final String CREDENTIALS_FILE_PATH = "src/test/data/com.securosys.primus.jce.credentials.properties";

    private static JCommander buildCreateCommand() {
        return JCommander.newBuilder()
                .addCommand("create", new CreateTdwCommand())
                .build();
    }

    // CAUTION For calling this function,
    //         see the related instructions in pom.xml in regard to Securosys Primus HSM (JCE security provider)
    private static void testValidatePrimusParameters() {

        assertDoesNotThrow(() -> {
            buildCreateCommand().parse("create", "-u", "https://domain.com:443/path1/path2/did.jsonl",
                    CommandParameterNames.PARAM_NAME_LONG_PRIMUS_CREDENTIALS, CREDENTIALS_FILE_PATH,
                    CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, "whatever"
            );
        });

        assertDoesNotThrow(() -> {
            buildCreateCommand().parse("create", "-u", "https://domain.com:443/path1/path2/did.jsonl",
                    CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_CREDENTIALS, CREDENTIALS_FILE_PATH,
                    CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS, "whatever"
            );
        });

        assertDoesNotThrow(() -> {
            buildCreateCommand().parse("create", "-u", "https://domain.com:443/path1/path2/did.jsonl",
                    CommandParameterNames.PARAM_NAME_LONG_PRIMUS_CREDENTIALS, CREDENTIALS_FILE_PATH,
                    CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS, "whatever"
            );
        });

        assertDoesNotThrow(() -> {
            buildCreateCommand().parse("create", "-u", "https://domain.com:443/path1/path2/did.jsonl",
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
                        Arrays.stream(new String[]{"create", "-u", "https://domain.com:443/path1/path2/did.jsonl"}),
                        Arrays.stream(args))
                .toArray(size -> (String[]) Array.newInstance(String.class, size));

        assertThrowsParameterException(() -> buildCreateCommand().parse(argz),
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