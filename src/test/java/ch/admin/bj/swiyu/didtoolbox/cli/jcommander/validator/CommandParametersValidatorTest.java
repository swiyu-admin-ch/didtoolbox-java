package ch.admin.bj.swiyu.didtoolbox.cli.jcommander.validator;

import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.CommandParameterNames;
import com.beust.jcommander.ParameterException;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class CommandParametersValidatorTest {

    private static final String INCOMPLETE_PRIMUS_MESSAGE = "The supplied Primus parameter(s) are incomplete";
    private static final String AMBIGUOUS_MESSAGE = "The supplied sources of (signing/verifying) keys are ambiguous";

    private final CommandParametersValidator validator = new CommandParametersValidator();

    private static Map<String, Object> supplied(String... parameterNames) {
        var parameters = new HashMap<String, Object>();
        for (var parameterName : parameterNames) {
            parameters.put(parameterName, "whatever");
        }
        return parameters;
    }

    private void assertRejected(Map<String, Object> parameters, String expectedMessageFragment) {
        var exc = assertThrowsExactly(ParameterException.class, () -> validator.validate(parameters)); // MUT
        assertTrue(exc.getMessage().contains(expectedMessageFragment), exc.getMessage());
    }

    static Stream<Named<List<String>>> completeKeySources() {
        return Stream.of(
                Named.of("Primus credentials + keystore alias", List.of(
                        CommandParameterNames.PARAM_NAME_LONG_PRIMUS_CREDENTIALS,
                        CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS)),
                Named.of("JKS file + alias + password", List.of(
                        CommandParameterNames.PARAM_NAME_LONG_JKS_FILE,
                        CommandParameterNames.PARAM_NAME_LONG_JKS_ALIAS,
                        CommandParameterNames.PARAM_NAME_LONG_JKS_PASSWORD)));
    }

    static Stream<Named<List<String>>> keySourceParamsClashingWithSigningKeyFile() {
        return Stream.of(
                Named.of("JKS alias", List.of(CommandParameterNames.PARAM_NAME_LONG_JKS_ALIAS)),
                Named.of("JKS password", List.of(CommandParameterNames.PARAM_NAME_LONG_JKS_PASSWORD)),
                Named.of("complete Primus (credentials + keystore alias)", List.of(
                        CommandParameterNames.PARAM_NAME_LONG_PRIMUS_CREDENTIALS,
                        CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS)));
    }

    @Test
    void validate_primusCredentialsAlone_rejectedAsIncomplete() {
        assertRejected(supplied(CommandParameterNames.PARAM_NAME_LONG_PRIMUS_CREDENTIALS), INCOMPLETE_PRIMUS_MESSAGE);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("completeKeySources")
    void validate_completeKeySource_accepted(List<String> parameterNames) {
        assertDoesNotThrow(() -> validator.validate(supplied(parameterNames.toArray(String[]::new)))); // MUT
    }

    @ParameterizedTest(name = "{0} and signing key file")
    @MethodSource("keySourceParamsClashingWithSigningKeyFile")
    void validate_keySourceParamsAndSigningKeyFile_rejectedAsAmbiguous(List<String> parameterNames) {
        var names = new ArrayList<>(parameterNames);
        names.add(CommandParameterNames.PARAM_NAME_LONG_SIGNING_KEY_FILE);

        assertRejected(supplied(names.toArray(String[]::new)), AMBIGUOUS_MESSAGE);
    }
}
