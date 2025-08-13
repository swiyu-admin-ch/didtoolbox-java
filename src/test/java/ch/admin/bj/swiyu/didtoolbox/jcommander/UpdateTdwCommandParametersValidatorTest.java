package ch.admin.bj.swiyu.didtoolbox.jcommander;

import com.beust.jcommander.JCommander;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.stream.Stream;

class UpdateTdwCommandParametersValidatorTest extends AbstractTdwCommandParametersValidatorTest {

    @Override
    protected JCommander buildCommandParser() {
        return JCommander.newBuilder()
                .addCommand(UpdateTdwCommand.COMMAND_NAME, new UpdateTdwCommand())
                .build();
    }

    @Override
    protected String[] appendToRequiredCommandArgs(String... args) {
        return Stream.concat(
                        Arrays.stream(new String[]{
                                UpdateTdwCommand.COMMAND_NAME,
                                CommandParameterNames.PARAM_NAME_SHORT_DID_LOG_FILE, dummyDidLogFile.getPath() // required
                        }),
                        Arrays.stream(args))
                .toArray(size -> (String[]) Array.newInstance(String.class, size));
    }

    /* Use it as template, as soon some class-specific test cases emerge
    @Test
    void testValidate() {
        // NOTE no need to call the super method explicitly here, as it will be called anyway (as long as annotated with @Test)
        //super.testAbstractValidate();
    }
     */
}