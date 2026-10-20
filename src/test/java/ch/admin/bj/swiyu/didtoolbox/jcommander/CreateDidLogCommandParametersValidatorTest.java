package ch.admin.bj.swiyu.didtoolbox.jcommander;

import ch.admin.bj.swiyu.didtoolbox.jcommander.validator.IdentifierRegistryUrlParameterValidator;
import com.beust.jcommander.JCommander;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

@SuppressWarnings("PMD")
class CreateDidLogCommandParametersValidatorTest extends AbstractCommandParametersValidatorTest {

    @Override
    protected JCommander buildCommandParser() {
        return JCommander.newBuilder()
                .addCommand(CreateDidLogCommand.COMMAND_NAME, new CreateDidLogCommand())
                .build();
    }

    @Override
    protected String[] appendToRequiredCommandArgs(String... args) {
        return Stream.concat(
                        Arrays.stream(new String[]{
                                CreateDidLogCommand.COMMAND_NAME,
                                "-u", "https://domain.com:443/path1/path2/did.jsonl" // required
                        }),
                        Arrays.stream(args))
                .toArray(size -> (String[]) Array.newInstance(String.class, size));
    }

    @Test
    void test_variousUrls() {
        var validator = new IdentifierRegistryUrlParameterValidator();
        assertThrowsParameterException(
                () -> validator.validate("-u", "http://example.test/aoeu")
                ,"must be a HTTPS");
        assertThrowsParameterException(
                () -> validator.validate("-u", "httpsfake://example.test/aoeu")
                ,"must be a regular HTTPS");
        assertDoesNotThrow(() -> validator.validate("-u", "https://example.test/aoeu"));
    }

}