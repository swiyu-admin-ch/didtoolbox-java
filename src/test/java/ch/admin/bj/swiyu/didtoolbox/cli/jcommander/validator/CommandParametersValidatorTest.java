package ch.admin.bj.swiyu.didtoolbox.cli.jcommander.validator;

import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.CommandParameterNames;
import com.beust.jcommander.ParameterException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@SuppressWarnings("PMD")
class CommandParametersValidatorTest {

    @Test
    void testPrimusParameters() {

        var validator = new CommandParametersValidator();

        List<Map<String, Object>> incompleteParams = List.of(
                Map.of(CommandParameterNames.PARAM_NAME_LONG_PRIMUS_CREDENTIALS, "whatever"),
                Map.of(CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, "whatever"),
                Map.of(CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD, "whatever"),
                Map.of(
                        CommandParameterNames.PARAM_NAME_LONG_PRIMUS_CREDENTIALS, "whatever",
                        CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD, "whatever"
                ),
                Map.of(
                        CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, "whatever",
                        CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD, "whatever"
                )
        );

        for (var params : incompleteParams) {
            assertThrowsParameterException(() -> validator.validate(params),
                    "The supplied Primus parameter(s) are incomplete"
            );
        }

        List<Map<String, Object>> completeParams = List.of(
                Map.of(),
                Map.of(
                        CommandParameterNames.PARAM_NAME_LONG_PRIMUS_CREDENTIALS, "whatever",
                        CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, "whatever"
                ),
                Map.of(
                        CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_CREDENTIALS, "whatever",
                        CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS, "whatever"
                ),
                Map.of(
                        CommandParameterNames.PARAM_NAME_LONG_PRIMUS_CREDENTIALS, "whatever",
                        CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, "whatever",
                        CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD, "whatever"
                )
        );

        for (var params : completeParams) {
            assertDoesNotThrow(() -> validator.validate(params));
        }
    }

    private static void assertThrowsParameterException(Executable executable, String containedInErrorMessage) {
        var exc = assertThrowsExactly(ParameterException.class, executable, "Expected: " + containedInErrorMessage);
        if (containedInErrorMessage != null) {
            assertTrue(exc.getMessage().contains(containedInErrorMessage));
        }
    }
}
