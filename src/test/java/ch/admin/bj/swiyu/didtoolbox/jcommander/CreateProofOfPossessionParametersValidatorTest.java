package ch.admin.bj.swiyu.didtoolbox.jcommander;

import com.beust.jcommander.JCommander;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.stream.Stream;

public class CreateProofOfPossessionParametersValidatorTest extends AbstractCommandParametersValidatorTest {

    @Override
    protected JCommander buildCommandParser() {
        return JCommander.newBuilder()
                .addCommand(CreateProofOfPossessionCommand.COMMAND_NAME, new CreateProofOfPossessionCommand())
                .build();
    }

    @Override
    protected String[] appendToRequiredCommandArgs(String... args) {
        return Stream.concat(
                        Arrays.stream(new String[]{
                                CreateProofOfPossessionCommand.COMMAND_NAME,
                                CommandParameterNames.PARAM_NAME_SHORT_NONCE, "nonce" // required
                        }),
                        Arrays.stream(args))
                .toArray(size -> (String[]) Array.newInstance(String.class, size));
    }
}
