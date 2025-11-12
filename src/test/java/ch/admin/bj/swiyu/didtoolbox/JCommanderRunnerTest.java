package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.jcommander.AbstractKeyMaterialDidLogCommand;
import ch.admin.bj.swiyu.didtoolbox.jcommander.CreateDidLogCommand;
import ch.admin.bj.swiyu.didtoolbox.jcommander.UpdateDidLogCommand;
import ch.admin.bj.swiyu.didtoolbox.jcommander.VerificationMethodParameters;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.internal.Console;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.security.spec.InvalidKeySpecException;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * The class was introduced for the sake of being able to test the CLI with no hassle involved.
 */
@SuppressWarnings("PMD")
class JCommanderRunnerTest extends AbstractUtilTestBase {

    private StringBuilder output;
    final private JCommander.Builder jCommanderBuilder = JCommander.newBuilder().console(new Console() {
        @Override
        public void print(String msg) {
        }

        @Override
        public void println(String msg) {
            output.append(msg);
        }

        @Override
        public char[] readPassword(boolean echoInput) {
            return new char[0];
        }
    });

    private static void setKeyMaterial(AbstractKeyMaterialDidLogCommand command) throws IOException, InvalidKeySpecException {
        command.assertionMethodKeys = Set.of(new VerificationMethodParameters("my-assert-key-01",
                JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/assert-key-01.pub"), "my-assert-key-01")));
        command.authenticationKeys = Set.of(new VerificationMethodParameters("my-auth-key-01",
                JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/auth-key-01.pub"), "my-auth-key-01")));
    }

    @BeforeEach
    void setUp() {
        output = new StringBuilder();
    }

    @Test
    void testRunCreateDidLogCommandWithKeyPrerotation() {

        // REMINDER By default, command.methodVersion is set to DidMethodEnum.WEBVH_1_0
        var command = new CreateDidLogCommand();

        command.forceOverwrite = true;
        // REMINDER Omitting signingKeyPemFile/verifyingKeyPemFiles denotes key pair generation by the command itself
        //command.signingKeyPemFile = TEST_SIGNING_KEY_FILES[0];
        //command.verifyingKeyPemFiles = Set.of(TEST_KEY_FILES[0]);
        command.nextVerifyingKeyPemFiles = Set.of(TEST_KEY_FILES[1], TEST_KEY_FILES[2]); // denotes "key pre-rotation"

        assertDoesNotThrow(() -> {

            command.identifierRegistryUrl = URL.of(new URI(TEST_DID_URL), null);

            setKeyMaterial(command); // essential

            new JCommanderRunner(jCommanderBuilder
                    .addCommand(CreateDidLogCommand.COMMAND_NAME, command)
                    .build(),
                    UpdateDidLogCommand.COMMAND_NAME
            ).runCreateDidLogCommand(command); // MUT
        });

        assertFalse(output.isEmpty());
        //System.out.println(output);
    }

    @Test
    void testRunUpdateDidLogCommand() {

        var command = new UpdateDidLogCommand();

        command.didLogFile = writeStringToTempFile(buildInitialWebVerifiableHistoryDidLogEntry(TEST_VERIFICATION_METHOD_KEY_PROVIDER_JKS));

        command.signingKeyPemFile = new File(TEST_DATA_PATH_PREFIX + "private.pem"); // must match the updateKey set by the initial entry
        // TODO Is setting command.verifyingKeyPemFiles irrelevant here?
        command.verifyingKeyPemFiles = Set.of(new File(TEST_DATA_PATH_PREFIX + "public.pem")); // must match the updateKey set by the initial entry

        assertDoesNotThrow(() -> {

            setKeyMaterial(command); // essential

            new JCommanderRunner(jCommanderBuilder
                    .addCommand(UpdateDidLogCommand.COMMAND_NAME, command)
                    .build(),
                    UpdateDidLogCommand.COMMAND_NAME
            ).runUpdateDidLogCommand(command); // MUT
        });

        assertFalse(output.isEmpty());
        //System.out.println(output);
    }

    @Test
    void testRunUpdateDidLogCommandWithKeyPrerotation() {

        var command = new UpdateDidLogCommand();

        command.didLogFile = writeStringToTempFile(buildInitialWebVerifiableHistoryDidLogEntryWithKeyPrerotation(Set.of(
                TEST_KEY_FILES[0] // the (single) pre-rotation key to be used when building the next DID log entry
        )));

        command.signingKeyPemFile = TEST_SIGNING_KEY_FILES[0]; // must match the pre-rotation key(s) set by the initial entry
        command.verifyingKeyPemFiles = Set.of(TEST_KEY_FILES[0]); // must match the pre-rotation key(s) set by the initial entry
        command.nextVerifyingKeyPemFiles = Set.of(TEST_KEY_FILES[1], TEST_KEY_FILES[2]); // denotes "key pre-rotation"

        assertDoesNotThrow(() -> {

            setKeyMaterial(command); // essential

            new JCommanderRunner(jCommanderBuilder
                    .addCommand(UpdateDidLogCommand.COMMAND_NAME, command)
                    .build(),
                    UpdateDidLogCommand.COMMAND_NAME
            ).runUpdateDidLogCommand(command); // MUT
        });

        assertFalse(output.isEmpty());
        //System.out.println(output);
    }

    @Test
    void testRunUpdateDidLogCommandUsingJks() {

        var command = new UpdateDidLogCommand();

        command.didLogFile = writeStringToTempFile(
                buildInitialWebVerifiableHistoryDidLogEntry(TEST_VERIFICATION_METHOD_KEY_PROVIDER_JKS) // matches "myalias" key from "mykeystore.jks"
        );

        command.jksFile = new File(TEST_DATA_PATH_PREFIX + "mykeystore.jks");
        command.jksPassword = "changeit";
        // REMINDER Setting to another key (e.g. "myalias2") should cause "Update key mismatch"
        command.jksAlias = "myalias"; // must match one set by the initial entry
        // REMINDER Setting command.verifyingKeyPemFiles has no effect in this case

        assertDoesNotThrow(() -> {

            setKeyMaterial(command); // essential

            new JCommanderRunner(jCommanderBuilder
                    .addCommand(UpdateDidLogCommand.COMMAND_NAME, command)
                    .build(),
                    UpdateDidLogCommand.COMMAND_NAME
            ).runUpdateDidLogCommand(command); // MUT
        });

        assertFalse(output.isEmpty());
        //System.out.println(output);
    }

    @Test
    void testRunUpdateDidLogCommandWithKeyPrerotationUsingJks() {

        var command = new UpdateDidLogCommand();

        command.didLogFile = writeStringToTempFile(buildInitialWebVerifiableHistoryDidLogEntryWithKeyPrerotation(Set.of(
                new File(TEST_DATA_PATH_PREFIX + "public.pem"), // matches "myalias" key from "mykeystore.jks"
                TEST_KEY_FILES[0]
        )));

        command.jksFile = new File(TEST_DATA_PATH_PREFIX + "mykeystore.jks");
        command.jksPassword = "changeit";
        command.jksAlias = "myalias"; // must match one the pre-rotation key(s) set by the initial entry
        // REMINDER Setting command.verifyingKeyPemFiles is optional, but the value MUST match one of the pre-rotation key(s) set by the initial entry
        //command.verifyingKeyPemFiles = Set.of(TEST_KEY_FILES[0]);
        //command.nextVerifyingKeyPemFiles = Set.of(TEST_KEY_FILES[0], TEST_KEY_FILES[1]);

        assertDoesNotThrow(() -> {

            setKeyMaterial(command); // essential

            new JCommanderRunner(jCommanderBuilder
                    .addCommand(UpdateDidLogCommand.COMMAND_NAME, command)
                    .build(),
                    UpdateDidLogCommand.COMMAND_NAME
            ).runUpdateDidLogCommand(command); // MUT
        });

        assertFalse(output.isEmpty());
        //System.out.println(output);
    }

    @Test
    void testMultipleRunUpdateDidLogCommandWithKeyPrerotationUsingJks() {

        var command1 = new UpdateDidLogCommand();

        command1.didLogFile = writeStringToTempFile(buildInitialWebVerifiableHistoryDidLogEntryWithKeyPrerotation(Set.of(
                new File(TEST_DATA_PATH_PREFIX + "public.pem"), // matches "myalias" key from "mykeystore.jks"
                TEST_KEY_FILES[0] // the key to rotate to when building the next entry
        )));

        command1.jksFile = new File(TEST_DATA_PATH_PREFIX + "mykeystore.jks");
        command1.jksPassword = "changeit";
        command1.jksAlias = "myalias"; // must match one the pre-rotation key(s) set by the initial entry
        // REMINDER Setting command1.verifyingKeyPemFiles is OPTIONAL, but the value MUST match one of the pre-rotation key(s) set by the initial entry
        //command1.verifyingKeyPemFiles = Set.of(TEST_KEY_FILES[0]);
        command1.nextVerifyingKeyPemFiles = Set.of(TEST_KEY_FILES[0], TEST_KEY_FILES[1]); // TEST_KEY_FILES[1] may be now also be used in the future

        assertDoesNotThrow(() -> {

            setKeyMaterial(command1); // essential

            new JCommanderRunner(jCommanderBuilder
                    .addCommand(UpdateDidLogCommand.COMMAND_NAME, command1)
                    .build(),
                    UpdateDidLogCommand.COMMAND_NAME
            ).runUpdateDidLogCommand(command1); // MUT
        });

        assertFalse(output.isEmpty());
        //System.out.println(output);

        var command2 = new UpdateDidLogCommand();

        command2.didLogFile = writeStringToTempFile(output.toString()); // built by the previous command1 run
        output = new StringBuilder(); // reset output buffer

        // CAUTION At this point, no appropriate JKS available for setting command1.jks* values, so get keys from the file system

        // Rotate to keypair TEST_SIGNING_KEY_FILES[1]/TEST_KEY_FILES[1]
        command2.signingKeyPemFile = TEST_SIGNING_KEY_FILES[1]; // must match one of the pre-rotation key(s) set by the initial entry
        command2.verifyingKeyPemFiles = Set.of(TEST_KEY_FILES[0], TEST_KEY_FILES[1]); // MUST be among pre-rotation key(s) set by the initial entry
        // CAUTION By leaving command2.nextVerifyingKeyPemFiles unset, "key pre-rotation" should be DEACTIVATED

        assertDoesNotThrow(() -> {

            setKeyMaterial(command2); // essential

            new JCommanderRunner(jCommanderBuilder
                    .addCommand(UpdateDidLogCommand.COMMAND_NAME, command2)
                    .build(),
                    UpdateDidLogCommand.COMMAND_NAME
            ).runUpdateDidLogCommand(command2); // MUT
        });

        assertFalse(output.isEmpty());
        //System.out.println(output);

        // CAUTION At this point, "key pre-rotation" is DEACTIVATED!

        var command3 = new UpdateDidLogCommand();

        command3.didLogFile = writeStringToTempFile(output.toString()); // built by the previous command1 run
        output = new StringBuilder(); // reset output buffer

        // CAUTION At this point, no appropriate JKS available for setting command1.jks* values, so get keys from the file system

        // Rotate back to keypair TEST_SIGNING_KEY_FILES[0]/TEST_KEY_FILES[0]
        command3.signingKeyPemFile = TEST_SIGNING_KEY_FILES[0]; // MUST match one of the pre-rotation key(s) set by the initial entry
        command3.verifyingKeyPemFiles = Set.of(TEST_KEY_FILES[0]); // MUST be among pre-rotation key(s) set by the initial entry

        assertDoesNotThrow(() -> {

            setKeyMaterial(command3); // essential

            new JCommanderRunner(jCommanderBuilder
                    .addCommand(UpdateDidLogCommand.COMMAND_NAME, command3)
                    .build(),
                    UpdateDidLogCommand.COMMAND_NAME
            ).runUpdateDidLogCommand(command3); // MUT
        });

        assertFalse(output.isEmpty());
        //System.out.println(output);
    }
}