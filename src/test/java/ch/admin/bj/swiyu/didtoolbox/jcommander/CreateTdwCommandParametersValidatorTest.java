package ch.admin.bj.swiyu.didtoolbox.jcommander;

import ch.admin.bj.swiyu.didtoolbox.CreateTdwCommand;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.stream.Stream;

import static ch.admin.bj.swiyu.didtoolbox.CreateTdwCommand.*;
import static org.junit.jupiter.api.Assertions.*;

class CreateTdwCommandParametersValidatorTest {

    private static final String CREDENTIALS_FILE_PATH = "src/test/data/com.securosys.primus.jce.credentials.properties";

    private static void testValidatePrimusParameters() {

        assertDoesNotThrow(() -> {
            var jc = JCommander.newBuilder()
                    .addCommand("create", new CreateTdwCommand())
                    .build();
            jc.parse("create", "-u", "https://domain.com:443/path1/path2/did.jsonl",
                    PARAM_NAME_LONG_PRIMUS_KEYSTORE, CREDENTIALS_FILE_PATH,
                    PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, "whatever",
                    PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD, "whatever"
            );
        });

        assertDoesNotThrow(() -> {
            var jc = JCommander.newBuilder()
                    .addCommand("create", new CreateTdwCommand())
                    .build();
            jc.parse("create", "-u", "https://domain.com:443/path1/path2/did.jsonl",
                    PARAM_NAME_SHORT_PRIMUS_KEYSTORE, CREDENTIALS_FILE_PATH,
                    PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS, "whatever",
                    PARAM_NAME_SHORT_PRIMUS_KEYSTORE_PASSWORD, "whatever"
            );
        });

        // No PARAM_NAME_*_PRIMUS_KEYSTORE_ALIAS
        // No PARAM_NAME_*_PRIMUS_KEYSTORE_PASSWORD

        assertCreateTdwCommandThrowsParameterException(
                PARAM_NAME_SHORT_PRIMUS_KEYSTORE, CREDENTIALS_FILE_PATH
        );

        assertCreateTdwCommandThrowsParameterException(
                PARAM_NAME_LONG_PRIMUS_KEYSTORE, CREDENTIALS_FILE_PATH
        );

        // No PARAM_NAME_*_PRIMUS_KEYSTORE
        // No PARAM_NAME_*_PRIMUS_KEYSTORE_PASSWORD

        /*
        assertCreateTdwCommandThrowsParameterException(
                PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS, "whatever"
        );

        assertCreateTdwCommandThrowsParameterException(
                PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, "whatever"
        );
        */

        // No PARAM_NAME_*_PRIMUS_KEYSTORE
        // No PARAM_NAME_*_PRIMUS_KEYSTORE_ALIAS

        assertCreateTdwCommandThrowsParameterException(
                PARAM_NAME_SHORT_PRIMUS_KEYSTORE_PASSWORD, "whatever"
        );

        assertCreateTdwCommandThrowsParameterException(
                PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD, "whatever"
        );

        // No PARAM_NAME_*_PRIMUS_KEYSTORE_PASSWORD

        /*
        assertCreateTdwCommandThrowsParameterException(
                PARAM_NAME_SHORT_PRIMUS_KEYSTORE, CREDENTIALS_FILE_PATH,
                PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS, "whatever"
        );

        assertCreateTdwCommandThrowsParameterException(
                PARAM_NAME_LONG_PRIMUS_KEYSTORE, CREDENTIALS_FILE_PATH,
                PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, "whatever"
        );
         */

        // No PARAM_NAME_*_PRIMUS_KEYSTORE_ALIAS

        assertCreateTdwCommandThrowsParameterException(
                PARAM_NAME_SHORT_PRIMUS_KEYSTORE, CREDENTIALS_FILE_PATH,
                PARAM_NAME_SHORT_PRIMUS_KEYSTORE_PASSWORD, "whatever"
        );

        assertCreateTdwCommandThrowsParameterException(
                PARAM_NAME_LONG_PRIMUS_KEYSTORE, CREDENTIALS_FILE_PATH,
                PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD, "whatever"
        );

        // No PARAM_NAME_*_PRIMUS_KEYSTORE

        /*
        assertCreateTdwCommandThrowsParameterException(
                PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS, "whatever",
                PARAM_NAME_SHORT_PRIMUS_KEYSTORE_PASSWORD, "whatever"
        );

        assertCreateTdwCommandThrowsParameterException(
                PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, "whatever",
                PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD, "whatever"
        );
         */
    }

    private static void assertCreateTdwCommandThrowsParameterException(String... args) {
        var argz = Stream.concat(
                        Arrays.stream(new String[]{"create", "-u", "https://domain.com:443/path1/path2/did.jsonl"}),
                        Arrays.stream(args))
                .toArray(size -> (String[]) Array.newInstance(String.class, size));

        assertThrowsParameterException(() -> JCommander.newBuilder()
                        .addCommand("create", new CreateTdwCommand())
                        .build().parse(argz),
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
        testValidatePrimusParameters();
    }
}