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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("PMD")
public class CreateProofOfPossessionParametersValidatorTest {

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
    void testShortParameters() {
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
                {
                        CommandParameterNames.PARAM_NAME_SHORT_SIGNING_KEY_FILE,
                        dummyPEMFile.getPath()
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

            final int aoeu = indexToSkip;

            var argumentsWithMissing = Stream.concat(
                    Stream.of(CreateProofOfPossessionCommand.COMMAND_NAME),
                    IntStream.range(0, arguments.length).filter(i -> i != aoeu).mapToObj(i -> arguments[i]).flatMap(Arrays::stream)
            ).toArray(String[]::new);
            assertThrows(ParameterException.class, () -> jCommander.parse(argumentsWithMissing));
        }
    }


    @Test
    void testLongParameters() {
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
                {
                        CommandParameterNames.PARAM_NAME_LONG_SIGNING_KEY_FILE,
                        dummyPEMFile.getPath()
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

            final int aoeu = indexToSkip;

            var argumentsWithMissing = Stream.concat(
                    Stream.of(CreateProofOfPossessionCommand.COMMAND_NAME),
                    IntStream.range(0, arguments.length).filter(i -> i != aoeu).mapToObj(i -> arguments[i]).flatMap(Arrays::stream)
            ).toArray(String[]::new);
            assertThrows(ParameterException.class, () -> jCommander.parse(argumentsWithMissing));
        }
    }

}
