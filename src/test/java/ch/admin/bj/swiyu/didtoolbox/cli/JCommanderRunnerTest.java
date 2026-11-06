package ch.admin.bj.swiyu.didtoolbox.cli;

import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.AbstractKeyMaterialDidLogCommand;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.CreateDidLogCommand;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.CreateProofOfPossessionCommand;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.DeactivateDidLogCommand;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.UpdateDidLogCommand;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.VerifyProofOfPossessionCommand;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.parameter.VerificationMethodParameters;
import ch.admin.bj.swiyu.didtoolbox.cryptography.JwkUtils;
import ch.admin.bj.swiyu.didtoolbox.cryptography.ProofOfPossessionJWSSigner;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.did.AbstractUtilTestBase;
import ch.admin.bj.swiyu.didtoolbox.did.DidLogMetaPeekerException;
import ch.admin.bj.swiyu.didtoolbox.did.webvh.WebVerifiableHistoryDidLogMetaPeeker;
import ch.admin.bj.swiyu.didtoolbox.pop.ProofOfPossessionCreator;
import ch.admin.bj.swiyu.didtoolbox.pop.ProofOfPossessionVerifier;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.internal.Console;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.nio.file.Path;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The class was introduced for the sake of being able to test the CLI with no hassle involved.
 */
@SuppressWarnings("PMD")
class JCommanderRunnerTest extends AbstractUtilTestBase {

    private StringBuilder output;
    private StringBuilder usage;
    private final JCommander.Builder jCommanderBuilder = JCommander.newBuilder().console(new Console() {
        @Override
        public void print(CharSequence charSequence) {
            usage.append(charSequence); // used by JCommander.usage
        }

        @Override
        public void println(CharSequence charSequence) {
            output.append(charSequence);
        }

        @Override
        public char[] readPassword(boolean echoInput) {
            return new char[0];
        }
    });

    private static void setKeyMaterial(AbstractKeyMaterialDidLogCommand command) throws IOException, InvalidKeySpecException {
        command.assertionMethodKeys = Set.of(new VerificationMethodParameters("my-assert-key-01",
                JwkUtils.loadECPublicJWKasJSON(Path.of("src/test/data/assert-key-01.pub"), "my-assert-key-01")));
        command.authenticationKeys = Set.of(new VerificationMethodParameters("my-auth-key-01",
                JwkUtils.loadECPublicJWKasJSON(Path.of("src/test/data/auth-key-01.pub"), "my-auth-key-01")));
    }

    @BeforeEach
    void setUp() {
        output = new StringBuilder();
        usage = new StringBuilder();
    }

    @Test
    void testRunPrintsUsageOnHelp(@TempDir Path tmpDir) {
        var command = new CreateDidLogCommand();
        command.help = true;

        assertDoesNotThrow(() -> new JCommanderRunner(jCommanderBuilder
                .addCommand(CreateDidLogCommand.COMMAND_NAME, command)
                .build(),
                CreateDidLogCommand.COMMAND_NAME,
                tmpDir.toString()
        ).run()); // MUT

        assertTrue(usage.toString().contains(CreateDidLogCommand.COMMAND_NAME));
        assertTrue(output.isEmpty());
        assertFalse(tmpDir.resolve("id_ed25519").toFile().exists()); // nothing generated
    }

    @Test
    void testRunUnknownCommandFails(@TempDir Path tmpDir) {
        assertThrowsExactly(CommandException.class, () -> new JCommanderRunner(jCommanderBuilder
                .addCommand(CreateDidLogCommand.COMMAND_NAME, new CreateDidLogCommand())
                .build(),
                "unknown",
                tmpDir.toString()
        ).run()); // MUT

        assertTrue(output.isEmpty());
        assertTrue(usage.isEmpty());
    }

    @Test
    void testRunCreateDidLogCommand(@TempDir Path tmpDir) {

        // REMINDER By default, command.methodVersion is set to DidMethodEnum.WEBVH_1_0
        var command = new CreateDidLogCommand();

        command.forceOverwrite = true;

        // REMINDER In case of CLI, Omitting signingKeyPemFile/verifyingKeyPemFiles denotes key pair generation by the command itself

        assertDoesNotThrow(() -> {

            command.identifierRegistryUrl = URL.of(new URI(TEST_DID_URL), null);

            // REMINDER In case of CLI, supplying no verification material would result in a DID document with generated auth/assert keys

            new JCommanderRunner(jCommanderBuilder
                    .addCommand(CreateDidLogCommand.COMMAND_NAME, command)
                    .build(),
                    CreateDidLogCommand.COMMAND_NAME,
                    tmpDir.toString()
            ).run(); // MUT
        });

        assertDoesNotThrow(() -> {
            var didLogMeta = WebVerifiableHistoryDidLogMetaPeeker.peek(output.toString());
            assertEquals(1, didLogMeta.getLastVersionNumber());

            // CAUTION The persisted key MUST be the one the DID log was created with, as the DID could never be updated otherwise
            var cryptoSuite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite(tmpDir.resolve("id_ed25519"));
            assertEquals(Set.of(cryptoSuite.getVerificationKeyMultibase()), didLogMeta.getParams().getUpdateKeys());
        });
    }

    @Test
    void testRunCreateDidLogCommandWithKeyPrerotation(@TempDir Path tmpDir) {

        // REMINDER By default, command.methodVersion is set to DidMethodEnum.WEBVH_1_0
        var command = new CreateDidLogCommand();

        command.forceOverwrite = true;
        // REMINDER In case of CLI, omitting signingKeyPemFile/verifyingKeyPemFiles denotes key pair generation by the command itself
        command.nextVerifyingKeyPemFiles = Set.of(TEST_KEY_FILES[1], TEST_KEY_FILES[2]); // denotes "key pre-rotation"

        assertDoesNotThrow(() -> {

            command.identifierRegistryUrl = URL.of(new URI(TEST_DID_URL), null);

            // REMINDER In case of CLI, supplying no verification material would result in a DID document with generated auth/assert keys

            new JCommanderRunner(jCommanderBuilder
                    .addCommand(CreateDidLogCommand.COMMAND_NAME, command)
                    .build(),
                    CreateDidLogCommand.COMMAND_NAME,
                    tmpDir.toString()
            ).run(); // MUT
        });

        var didLogMeta = assertDoesNotThrow(() -> WebVerifiableHistoryDidLogMetaPeeker.peek(output.toString()));
        assertTrue(didLogMeta.isKeyPreRotationActivated());
        assertTrue(didLogMeta.isPreRotatedUpdateKey(TEST_KEYS[1][1]));
        assertTrue(didLogMeta.isPreRotatedUpdateKey(TEST_KEYS[2][1]));
    }

    @Test
    void testRunUpdateDidLogCommand() {
        var command = new UpdateDidLogCommand();
        command.didLogFile = writeStringToTempFile(buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE_JKS));
        command.signingKeyPemFile = new File(TEST_DATA_PATH_PREFIX + "private.pem"); // must match the updateKey set by the initial entry

        assertDoesNotThrow(() -> {

            setKeyMaterial(command); // essential

            new JCommanderRunner(jCommanderBuilder
                    .addCommand(UpdateDidLogCommand.COMMAND_NAME, command)
                    .build(),
                    UpdateDidLogCommand.COMMAND_NAME
            ).run(); // MUT
        });

        assertDoesNotThrow(() -> assertEquals(2, WebVerifiableHistoryDidLogMetaPeeker.peek(output.toString()).getLastVersionNumber())); // there should be another entry i.e. one more
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
            ).run(); // MUT
        });

        var didLogMeta = assertDoesNotThrow(() -> WebVerifiableHistoryDidLogMetaPeeker.peek(output.toString()));
        assertEquals(2, didLogMeta.getLastVersionNumber()); // there should be another entry i.e. one more
        assertTrue(didLogMeta.isPreRotatedUpdateKey(TEST_KEYS[1][1]));
        assertTrue(didLogMeta.isPreRotatedUpdateKey(TEST_KEYS[2][1]));
    }

    @Test
    void testRunUpdateDidLogCommandUsingJks() {
        var command = new UpdateDidLogCommand();
        command.didLogFile = writeStringToTempFile(
                buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE_JKS) // matches "myalias" key from "mykeystore.jks"
        );
        command.jksFile = new File(TEST_DATA_PATH_PREFIX + "mykeystore.jks");
        command.jksPassword = "changeit";
        // REMINDER Setting to another key (e.g. "myalias2") should cause "Update key mismatch"
        command.jksAlias = "myalias"; // must match one set by the initial entry

        assertDoesNotThrow(() -> {
            setKeyMaterial(command); // essential
            new JCommanderRunner(jCommanderBuilder
                    .addCommand(UpdateDidLogCommand.COMMAND_NAME, command)
                    .build(),
                    UpdateDidLogCommand.COMMAND_NAME
            ).run(); // MUT
        });

        assertDoesNotThrow(() -> assertEquals(2, WebVerifiableHistoryDidLogMetaPeeker.peek(output.toString()).getLastVersionNumber())); // there should be another entry i.e. one more
    }

    @Test
    void testRunUpdateDidLogCommandWithKeyPrerotationUsingJksThrowsIllegalSigningKeyCommandException() {
        var command = new UpdateDidLogCommand();
        command.didLogFile = writeStringToTempFile(buildInitialWebVerifiableHistoryDidLogEntryWithKeyPrerotation(Set.of(
                TEST_KEY_FILES[0]
        )));
        command.verifyingKeyPemFiles = Set.of(TEST_KEY_FILES[0]); // matches the pre-rotation key set by the initial entry
        command.jksFile = new File(TEST_DATA_PATH_PREFIX + "mykeystore.jks");
        command.jksPassword = "changeit";
        // IMPORTANT The key does not match the pre-rotation key set by the initial entry thus ILLEGAL
        command.jksAlias = "myalias";

        var exc = assertThrowsExactly(CommandException.class, () -> {
            setKeyMaterial(command); // essential

            new JCommanderRunner(jCommanderBuilder
                    .addCommand(UpdateDidLogCommand.COMMAND_NAME, command)
                    .build(),
                    UpdateDidLogCommand.COMMAND_NAME
            ).run(); // MUT
        });
        assertEquals("Illegal signing (private) ed25519 key supplied", exc.getMessage());

        // Expect no output, as command failed
        assertTrue(output.isEmpty());
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
        command1.verifyingKeyPemFiles = Set.of(TEST_KEY_FILES[0], new File(TEST_DATA_PATH_PREFIX + "public.pem"));
        command1.nextVerifyingKeyPemFiles = Set.of(TEST_KEY_FILES[1]); // TEST_KEY_FILES[1] may be now also be used in the future

        assertDoesNotThrow(() -> {
            setKeyMaterial(command1); // essential

            new JCommanderRunner(jCommanderBuilder
                    .addCommand(UpdateDidLogCommand.COMMAND_NAME, command1)
                    .build(),
                    UpdateDidLogCommand.COMMAND_NAME
            ).run(); // MUT
        });

        var didLogMeta = assertDoesNotThrow(() -> WebVerifiableHistoryDidLogMetaPeeker.peek(output.toString()));
        assertEquals(2, didLogMeta.getLastVersionNumber()); // there should be another entry i.e. one more
        assertTrue(didLogMeta.isPreRotatedUpdateKey(TEST_KEYS[1][1]));

        var command2 = new UpdateDidLogCommand();
        command2.didLogFile = writeStringToTempFile(output.toString()); // built by the previous command1 run
        output = new StringBuilder(); // reset output buffer
        // CAUTION At this point, no appropriate JKS available for setting command2.jks* values, so get keys from the file system
        // Rotate to keypair TEST_SIGNING_KEY_FILES[1]/TEST_KEY_FILES[1]
        command2.signingKeyPemFile = TEST_SIGNING_KEY_FILES[1]; // must match one of the pre-rotation key(s) set by the initial entry
        command2.verifyingKeyPemFiles = Set.of(TEST_KEY_FILES[1]); // MUST be among pre-rotation key(s) set by the initial entry
        // CAUTION By leaving command2.nextVerifyingKeyPemFiles unset, "key pre-rotation" should be DEACTIVATED

        assertDoesNotThrow(() -> {
            setKeyMaterial(command2); // essential

            new JCommanderRunner(jCommanderBuilder
                    .addCommand(UpdateDidLogCommand.COMMAND_NAME, command2)
                    .build(),
                    UpdateDidLogCommand.COMMAND_NAME
            ).run(); // MUT
        });

        didLogMeta = assertDoesNotThrow(() -> WebVerifiableHistoryDidLogMetaPeeker.peek(output.toString()));
        assertEquals(3, didLogMeta.getLastVersionNumber());
        assertFalse(didLogMeta.isKeyPreRotationActivated()); // CAUTION At this point, "key pre-rotation" is DEACTIVATED!

        var command3 = new UpdateDidLogCommand();
        command3.didLogFile = writeStringToTempFile(output.toString()); // built by the previous command2 run
        output = new StringBuilder(); // reset output buffer
        // CAUTION At this point, no appropriate JKS available for setting command3.jks* values, so get keys from the file system
        command3.signingKeyPemFile = TEST_SIGNING_KEY_FILES[1];

        assertDoesNotThrow(() -> {
            setKeyMaterial(command3); // essential

            new JCommanderRunner(jCommanderBuilder
                    .addCommand(UpdateDidLogCommand.COMMAND_NAME, command3)
                    .build(),
                    UpdateDidLogCommand.COMMAND_NAME
            ).run(); // MUT
        });

        assertDoesNotThrow(() -> assertEquals(4, WebVerifiableHistoryDidLogMetaPeeker.peek(output.toString()).getLastVersionNumber()));
    }

    @Test
    void testRunDeactivateDidLogCommand() {
        var didLog = buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE_JKS);

        var command = new DeactivateDidLogCommand();
        command.didLogFile = writeStringToTempFile(didLog);
        command.signingKeyPemFile = new File(TEST_DATA_PATH_PREFIX + "private.pem"); // must match the updateKey set by the initial entry

        assertDoesNotThrow(() -> new JCommanderRunner(jCommanderBuilder
                .addCommand(DeactivateDidLogCommand.COMMAND_NAME, command)
                .build(),
                DeactivateDidLogCommand.COMMAND_NAME
        ).run()); // MUT

        assertTrue(output.toString().startsWith(didLog.trim())); // the supplied DID log comes first
        assertEquals(2, output.toString().lines().count()); // followed by the deactivating entry

        var exc = assertThrowsExactly(DidLogMetaPeekerException.class, () -> WebVerifiableHistoryDidLogMetaPeeker.peek(output.toString()));
        assertTrue(exc.getMessage().contains("Document has been deactivated"));
    }

    @Test
    void testRunCreateProofOfPossessionCommand() {
        var didLog = buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE);

        var command = new CreateProofOfPossessionCommand();
        command.didLog = writeStringToTempFile(didLog);
        command.nonce = "my_nonce";
        command.signingKeyPemFile = new File(TEST_DATA_PATH_PREFIX + "assert-key-01"); // must match the key denoted by the kid

        assertDoesNotThrow(() -> {

            command.kid = WebVerifiableHistoryDidLogMetaPeeker.peek(didLog).getDidDoc().getId() + "#my-assert-key-01";

            new JCommanderRunner(jCommanderBuilder
                    .addCommand(CreateProofOfPossessionCommand.COMMAND_NAME, command)
                    .build(),
                    CreateProofOfPossessionCommand.COMMAND_NAME
            ).run(); // MUT
        });

        var jwt = assertDoesNotThrow(() -> SignedJWT.parse(output.toString()));
        assertEquals(command.kid, jwt.getHeader().getKeyID());
        assertDoesNotThrow(() -> new ProofOfPossessionVerifier(didLog).verify(jwt, command.nonce));
    }

    @Test
    void testRunVerifyProofOfPossessionCommand() {
        var didLog = buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE);

        var command = new VerifyProofOfPossessionCommand();
        command.didLogFile = writeStringToTempFile(didLog);
        command.nonce = "my_nonce";

        assertDoesNotThrow(() -> {

            command.jwt = new ProofOfPossessionCreator(ProofOfPossessionJWSSigner.of(
                    Path.of(TEST_DATA_PATH_PREFIX + "assert-key-01"),
                    WebVerifiableHistoryDidLogMetaPeeker.peek(didLog).getDidDoc().getId() + "#my-assert-key-01"
            )).create(command.nonce, Duration.ofDays(1));

            new JCommanderRunner(jCommanderBuilder
                    .addCommand(VerifyProofOfPossessionCommand.COMMAND_NAME, command)
                    .build(),
                    VerifyProofOfPossessionCommand.COMMAND_NAME
            ).run(); // MUT
        });

        assertEquals("Provided JWT is valid.", output.toString());
    }
}
