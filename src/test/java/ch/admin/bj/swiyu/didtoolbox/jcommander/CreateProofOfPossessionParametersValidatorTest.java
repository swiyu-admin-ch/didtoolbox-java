package ch.admin.bj.swiyu.didtoolbox.jcommander;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

@SuppressWarnings("PMD")
class CreateProofOfPossessionParametersValidatorTest {

    private File dummyDidLogFile;
    private File dummyPEMFile;
    private JCommander jCommander;

    @BeforeEach
    void setUp() throws IOException {
        assertDoesNotThrow(() -> this.jCommander = JCommander.newBuilder()
                .addCommand(CreateProofOfPossessionCommand.COMMAND_NAME, new CreateProofOfPossessionCommand())
                .build());

        dummyDidLogFile = File.createTempFile("my-did", ".jsonl");
        dummyPEMFile = new File("src/test/data/assert-key-01");
    }

    @Test
    void testPemFileParameters() {
        String[] requiredParams = {
                CreateProofOfPossessionCommand.COMMAND_NAME,
                CommandParameterNames.PARAM_NAME_SHORT_NONCE,
                "myNonce",
                CommandParameterNames.PARAM_NAME_SHORT_KID,
                "my_example_kid",
                CommandParameterNames.PARAM_NAME_SHORT_DID_LOG_FILE,
                dummyDidLogFile.getPath()
        };
        String[] fileParam = {CommandParameterNames.PARAM_NAME_LONG_SIGNING_KEY_FILE, dummyPEMFile.getPath()};

        var command = new CreateProofOfPossessionCommand();
        this.jCommander = JCommander.newBuilder()
                .addCommand(CreateProofOfPossessionCommand.COMMAND_NAME, command)
                .build();

        var argumentsWithMissing = Stream.concat(
                Arrays.stream(requiredParams),
                Stream.of(fileParam)
        ).toArray(String[]::new);
        assertDoesNotThrow(() -> jCommander.parse(argumentsWithMissing));
        assertEquals(command.signingKeyPemFile.toPath(), dummyPEMFile.toPath());
    }

    @Test
    void testPrimusParameters() {
        String[] requiredParams = {
                CreateProofOfPossessionCommand.COMMAND_NAME,
                CommandParameterNames.PARAM_NAME_SHORT_NONCE,
                "myNonce",
                CommandParameterNames.PARAM_NAME_SHORT_KID,
                "my_example_kid",
                CommandParameterNames.PARAM_NAME_SHORT_DID_LOG_FILE,
                dummyDidLogFile.getPath()
        };
        String[] primusParams = {
                CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS, "alias",
                CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD, "password",
        };

        var command = new CreateProofOfPossessionCommand();
        this.jCommander = JCommander.newBuilder()
                .addCommand(CreateProofOfPossessionCommand.COMMAND_NAME, command)
                .build();

        var argumentsWithMissing = Stream.concat(
                Arrays.stream(requiredParams),
                Stream.of(primusParams)
        ).toArray(String[]::new);
        var e = assertThrowsExactly(ParameterException.class, () -> jCommander.parse(argumentsWithMissing));
        assertTrue(e.getMessage().contains("The supplied Primus parameter(s) are incomplete"));
    }


    @Test
    void testRequiredParametersShort() {
        String[][] arguments = {
                {
                        CommandParameterNames.PARAM_NAME_SHORT_NONCE,
                        "myNonce"
                },
                {
                        CommandParameterNames.PARAM_NAME_SHORT_KID,
                        "my_example_kid"
                },
                {
                        CommandParameterNames.PARAM_NAME_SHORT_DID_LOG_FILE,
                        dummyDidLogFile.getPath()
                },
        };

        var allArguments = Stream.concat(
                Stream.of(CreateProofOfPossessionCommand.COMMAND_NAME),
                Arrays.stream(arguments).flatMap(Arrays::stream)
        ).toArray(String[]::new);
        assertDoesNotThrow(() -> jCommander.parse(allArguments));

        for (int indexToSkip = 0; indexToSkip < arguments.length; indexToSkip++) {
            this.jCommander = JCommander.newBuilder()
                    .addCommand(CreateProofOfPossessionCommand.COMMAND_NAME, new CreateProofOfPossessionCommand())
                    .build();

            final int skip = indexToSkip;

            var argumentsWithMissing = Stream.concat(
                    Stream.of(CreateProofOfPossessionCommand.COMMAND_NAME),
                    IntStream.range(0, arguments.length).filter(i -> i != skip).mapToObj(i -> arguments[i]).flatMap(Arrays::stream)
            ).toArray(String[]::new);
            assertThrows(ParameterException.class, () -> jCommander.parse(argumentsWithMissing));
        }
    }

    @Test
    void testRequiredParametersLong() {
        String[][] arguments = {
                {
                        CommandParameterNames.PARAM_NAME_LONG_NONCE,
                        "myNonce"
                },
                {
                        CommandParameterNames.PARAM_NAME_LONG_KID,
                        "my_example_kid"
                },
                {
                        CommandParameterNames.PARAM_NAME_LONG_DID_LOG_FILE,
                        dummyDidLogFile.getPath()
                },
        };

        var allArguments = Stream.concat(
                Stream.of(CreateProofOfPossessionCommand.COMMAND_NAME),
                Arrays.stream(arguments).flatMap(Arrays::stream)
        ).toArray(String[]::new);
        assertDoesNotThrow(() -> jCommander.parse(allArguments));

        for (int indexToSkip = 0; indexToSkip < arguments.length; indexToSkip++) {
            this.jCommander = JCommander.newBuilder()
                    .addCommand(CreateProofOfPossessionCommand.COMMAND_NAME, new CreateProofOfPossessionCommand())
                    .build();

            final int skip = indexToSkip;

            var argumentsWithMissing = Stream.concat(
                    Stream.of(CreateProofOfPossessionCommand.COMMAND_NAME),
                    IntStream.range(0, arguments.length).filter(i -> i != skip).mapToObj(i -> arguments[i]).flatMap(Arrays::stream)
            ).toArray(String[]::new);
            assertThrows(ParameterException.class, () -> jCommander.parse(argumentsWithMissing));
        }
    }

}
