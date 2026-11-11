package ch.admin.bj.swiyu.didtoolbox.cli;

import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.*;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.parameter.VerificationMethodParameters;
import ch.admin.bj.swiyu.didtoolbox.cli.keymaterial.GeneratedKeyPairStore;
import ch.admin.bj.swiyu.didtoolbox.cryptography.JwkUtils;
import ch.admin.bj.swiyu.didtoolbox.cryptography.ProofOfPossessionJWSSigner;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import ch.admin.bj.swiyu.didtoolbox.did.AbstractUtilTestBase;
import ch.admin.bj.swiyu.didtoolbox.did.DidLogMetaPeekerException;
import ch.admin.bj.swiyu.didtoolbox.did.model.DidMethodEnum;
import ch.admin.bj.swiyu.didtoolbox.did.tdw.TdwDidLogMetaPeeker;
import ch.admin.bj.swiyu.didtoolbox.did.webvh.WebVerifiableHistoryDidLogMetaPeeker;
import ch.admin.bj.swiyu.didtoolbox.pop.ProofOfPossessionCreator;
import ch.admin.bj.swiyu.didtoolbox.pop.ProofOfPossessionVerifier;
import ch.admin.bj.swiyu.didtoolbox.pop.ProofOfPossessionVerifierException;
import ch.admin.eid.did_sidekicks.DidDoc;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import com.beust.jcommander.internal.Console;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The class was introduced for the sake of being able to test the CLI with no hassle involved.
 */
@SuppressWarnings("PMD")
class JCommanderRunnerTest extends AbstractUtilTestBase {

    private static final String GENERATED_KEY_FILE_NAME = "id_ed25519"; // the private key file written by GeneratedKeyPairStore

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

    private static void setKeyMaterial(KeyMaterialDidLogCommand command) throws IOException, InvalidKeySpecException {
        setKeyMaterial(command, "my-assert-key-01", "my-auth-key-01");
    }

    private static void setKeyMaterial(KeyMaterialDidLogCommand command, String assertionKeyName, String authenticationKeyName) throws IOException, InvalidKeySpecException {
        command.assertionMethodKeys = Set.of(new VerificationMethodParameters(assertionKeyName,
                JwkUtils.loadECPublicJWKasJSON(Path.of("src/test/data/assert-key-01.pub"), assertionKeyName)));
        command.authenticationKeys = Set.of(new VerificationMethodParameters(authenticationKeyName,
                JwkUtils.loadECPublicJWKasJSON(Path.of("src/test/data/auth-key-01.pub"), authenticationKeyName)));
    }

    private static void assertDidDocFeaturesKeys(DidDoc didDoc, String... keyNames) {
        for (var keyName : keyNames) {
            assertDoesNotThrow(() -> assertNotNull(didDoc.getKeyByMethodId(didDoc.getId() + "#" + keyName)), keyName);
        }
    }

    @BeforeEach
    void setUp() {
        output = new StringBuilder();
        usage = new StringBuilder();
    }

    private void run(String commandName, CommandBase command, Path keyDir) throws Exception { // NOPMD SignatureDeclareThrowsException: propagates JCommanderRunner.run, which declares Exception
        new JCommanderRunner(jCommanderBuilder.addCommand(commandName, command).build(), commandName, keyDir.toString()).run();
    }

    private static File writeDidLog(Path dir, String didLog) throws IOException {
        return Files.writeString(dir.resolve("did.jsonl"), didLog).toFile();
    }

    private static String persistedKey(Path keyDir) throws VcDataIntegrityCryptographicSuiteException {
        return new EdDsaJcs2022VcDataIntegrityCryptographicSuite(keyDir.resolve(GENERATED_KEY_FILE_NAME)).getVerificationKeyMultibase();
    }

    private static Stream<Arguments> allCommands() {
        return Stream.of(
                Arguments.of(CreateDidLogCommand.COMMAND_NAME, new CreateDidLogCommand()),
                Arguments.of(UpdateDidLogCommand.COMMAND_NAME, new UpdateDidLogCommand()),
                Arguments.of(DeactivateDidLogCommand.COMMAND_NAME, new DeactivateDidLogCommand()),
                Arguments.of(CreateProofOfPossessionCommand.COMMAND_NAME, new CreateProofOfPossessionCommand()),
                Arguments.of(VerifyProofOfPossessionCommand.COMMAND_NAME, new VerifyProofOfPossessionCommand()));
    }

    @ParameterizedTest(name = "For command: {0}")
    @MethodSource("allCommands")
    void run_helpRequested_printsUsageOnly(String commandName, CommandBase command, @TempDir Path tmpDir) {
        command.help = true;
        // Listed by the root usage only, so it tells the command's own usage apart from the root one
        var decoyCommandName = "decoy-command";

        assertDoesNotThrow(() -> new JCommanderRunner(jCommanderBuilder
                .addCommand(commandName, command)
                .addCommand(decoyCommandName, new VerifyProofOfPossessionCommand())
                .build(),
                commandName,
                tmpDir.toString()
        ).run()); // MUT

        assertTrue(usage.toString().contains(commandName));
        assertFalse(usage.toString().contains(decoyCommandName));
        assertTrue(output.isEmpty());
        assertEquals(0, tmpDir.toFile().list().length); // nothing generated
    }

    @Test
    void run_unknownCommand_throwsCommandException(@TempDir Path tmpDir) {
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
    void run_createDidLog_printsLogAndPersistsGeneratedKey(@TempDir Path tmpDir) {

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
            var cryptoSuite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite(tmpDir.resolve(GENERATED_KEY_FILE_NAME));
            assertEquals(Set.of(cryptoSuite.getVerificationKeyMultibase()), didLogMeta.getParams().getUpdateKeys());
        });
    }

    @Test
    void run_createDidLogWithKeyPrerotation_printsLogWithPrerotatedKeys(@TempDir Path tmpDir) {

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
    void run_updateDidLog_appendsEntry() {
        var command = new UpdateDidLogCommand();
        command.didLogFile = writeStringToTempFile(buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE_JKS));
        command.signingKeyPemFile = new File(TEST_DATA_PATH_PREFIX + "private.pem"); // must match the updateKey set by the initial entry

        assertDoesNotThrow(() -> {

            // CAUTION The key names must differ from the ones featured by the initial entry, so that the assertions below cannot be satisfied by it
            setKeyMaterial(command, "rotated-assert", "rotated-auth"); // essential

            new JCommanderRunner(jCommanderBuilder
                    .addCommand(UpdateDidLogCommand.COMMAND_NAME, command)
                    .build(),
                    UpdateDidLogCommand.COMMAND_NAME
            ).run(); // MUT
        });

        var didLogMeta = assertDoesNotThrow(() -> WebVerifiableHistoryDidLogMetaPeeker.peek(output.toString()));
        assertEquals(2, didLogMeta.getLastVersionNumber()); // there should be another entry i.e. one more
        assertDidDocFeaturesKeys(didLogMeta.getDidDoc(), "rotated-assert", "rotated-auth");
    }

    @Test
    void run_updateDidLogWithKeyPrerotation_appendsEntryWithNextPrerotatedKeys() {
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
    void run_updateDidLogUsingJks_appendsEntry() {
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
    void run_updateDidLogWithKeyPrerotationAndNonPrerotatedJksKey_throwsCommandException() {
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
    void run_repeatedUpdateDidLogWithKeyPrerotation_rotatesKeysAndDeactivatesPrerotation() {
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
    void run_deactivateDidLog_appendsDeactivatingEntry() {
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
    void run_createProofOfPossession_printsValidJwt() {
        var didLog = buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE);

        var command = new CreateProofOfPossessionCommand();
        command.didLog = writeStringToTempFile(didLog);
        command.nonce = "my_nonce";
        command.signingKeyPemFile = new File(TEST_DATA_PATH_PREFIX + "assert-key-01"); // must match the key denoted by the kid

        // REMINDER The exp claim is serialized in whole seconds
        var before = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        assertDoesNotThrow(() -> {

            command.kid = WebVerifiableHistoryDidLogMetaPeeker.peek(didLog).getDidDoc().getId() + "#my-assert-key-01";

            new JCommanderRunner(jCommanderBuilder
                    .addCommand(CreateProofOfPossessionCommand.COMMAND_NAME, command)
                    .build(),
                    CreateProofOfPossessionCommand.COMMAND_NAME
            ).run(); // MUT
        });
        var after = Instant.now();

        var jwt = assertDoesNotThrow(() -> SignedJWT.parse(output.toString()));
        assertEquals(command.kid, jwt.getHeader().getKeyID());
        assertDoesNotThrow(() -> new ProofOfPossessionVerifier(didLog).verify(jwt, command.nonce));

        // as promised by the command description, the JWT expires after 24 hours
        var exp = assertDoesNotThrow(() -> jwt.getJWTClaimsSet().getExpirationTime().toInstant());
        assertFalse(exp.isBefore(before.plus(Duration.ofDays(1))), exp.toString());
        assertFalse(exp.isAfter(after.plus(Duration.ofDays(1))), exp.toString());
    }

    @Test
    void run_verifyProofOfPossession_printsValidMessage() {
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

    @Test
    void run_verifyProofOfPossessionWrongNonce_throwsCommandException(@TempDir Path tmpDir) throws Exception {
        var didLog = buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE);

        var command = new VerifyProofOfPossessionCommand();
        command.didLogFile = writeDidLog(tmpDir, didLog);
        command.jwt = new ProofOfPossessionCreator(ProofOfPossessionJWSSigner.of(
                Path.of(TEST_DATA_PATH_PREFIX + "assert-key-01"),
                WebVerifiableHistoryDidLogMetaPeeker.peek(didLog).getDidDoc().getId() + "#my-assert-key-01"
        )).create("my_nonce", Duration.ofDays(1));
        command.nonce = "another_nonce"; // does not match the one the JWT was created for

        var exc = assertThrowsExactly(CommandException.class, () -> run(VerifyProofOfPossessionCommand.COMMAND_NAME, command, tmpDir)); // MUT

        assertTrue(exc.getMessage().contains("Provided JWT is invalid"), exc.getMessage());
        assertInstanceOf(ProofOfPossessionVerifierException.class, exc.getCause());
        assertTrue(output.isEmpty());
    }

    @Test
    void run_updateTdwDidLog_appendsTdwEntry(@TempDir Path tmpDir) throws Exception {
        var didLog = buildInitialTdwDidLogEntry(TEST_CRYPTO_SUITE_JKS);
        var command = new UpdateDidLogCommand();
        command.didLogFile = writeDidLog(tmpDir, didLog + System.lineSeparator()); // as printed by the CLI, the trailing line separator must not end up in between
        command.signingKeyPemFile = new File(TEST_DATA_PATH_PREFIX + "private.pem"); // must match the updateKey set by the initial entry
        setKeyMaterial(command); // essential

        run(UpdateDidLogCommand.COMMAND_NAME, command, tmpDir); // MUT

        assertTrue(output.toString().startsWith(didLog.trim())); // the supplied DID log comes first
        assertEquals(2, output.toString().lines().count()); // followed by the new entry
        var didLogMeta = TdwDidLogMetaPeeker.peek(output.toString());
        assertEquals(2, didLogMeta.getLastVersionNumber());
        assertEquals(DidMethodEnum.TDW_0_3, didLogMeta.getParams().getDidMethodEnum());
    }

    @Test
    void run_deactivateTdwDidLog_appendsDeactivatingTdwEntry(@TempDir Path tmpDir) throws Exception {
        var didLog = buildInitialTdwDidLogEntry(TEST_CRYPTO_SUITE_JKS);
        var command = new DeactivateDidLogCommand();
        command.didLogFile = writeDidLog(tmpDir, didLog + System.lineSeparator()); // as printed by the CLI, the trailing line separator must not end up in between
        command.signingKeyPemFile = new File(TEST_DATA_PATH_PREFIX + "private.pem"); // must match the updateKey set by the initial entry

        run(DeactivateDidLogCommand.COMMAND_NAME, command, tmpDir); // MUT

        assertTrue(output.toString().startsWith(didLog.trim())); // the supplied DID log comes first
        assertEquals(2, output.toString().lines().count()); // followed by the deactivating entry

        // CAUTION The "exactly" part matters: its Malformed* subclass would denote an entry not being a did:tdw one
        var exc = assertThrowsExactly(DidLogMetaPeekerException.class, () -> TdwDidLogMetaPeeker.peek(output.toString()));
        assertTrue(exc.getMessage().contains("Document has been deactivated"), exc.getMessage());
    }

    @ParameterizedTest(name = "Generating the next key: {0}")
    @ValueSource(booleans = {true, false})
    void run_updateDidLogGeneratingKey_persistedKeyIsNextOrUpdateKey(boolean generateNextKey, @TempDir Path tmpDir) throws Exception {
        var command = new UpdateDidLogCommand();
        command.didLogFile = writeDidLog(tmpDir, buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE_JKS));
        command.signingKeyPemFile = new File(TEST_DATA_PATH_PREFIX + "private.pem"); // must match the updateKey set by the initial entry
        command.shouldGenerateNextVerifyingKeyPem = generateNextKey;
        command.shouldGenerateVerifyingKeyPem = !generateNextKey;
        setKeyMaterial(command); // essential

        run(UpdateDidLogCommand.COMMAND_NAME, command, tmpDir); // MUT

        var didLogMeta = WebVerifiableHistoryDidLogMetaPeeker.peek(output.toString());
        var persisted = persistedKey(tmpDir);
        assertEquals(2, didLogMeta.getLastVersionNumber());
        assertEquals(generateNextKey, didLogMeta.isKeyPreRotationActivated());
        assertEquals(generateNextKey, didLogMeta.isPreRotatedUpdateKey(persisted));
        assertEquals(!generateNextKey, didLogMeta.getParams().getUpdateKeys().contains(persisted));
    }

    @Test
    void run_updateDidLogWithBothGenerateFlags_throwsParameterException(@TempDir Path tmpDir) throws Exception {
        var command = new UpdateDidLogCommand();
        command.didLogFile = writeDidLog(tmpDir, buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE_JKS));
        command.signingKeyPemFile = new File(TEST_DATA_PATH_PREFIX + "private.pem");
        command.shouldGenerateNextVerifyingKeyPem = true;
        command.shouldGenerateVerifyingKeyPem = true;
        setKeyMaterial(command); // essential

        var exc = assertThrowsExactly(ParameterException.class, () -> run(UpdateDidLogCommand.COMMAND_NAME, command, tmpDir)); // MUT

        assertTrue(exc.getMessage().contains(CommandParameterNames.PARAM_NAME_LONG_GENERATE_NEW_VERIFYING_KEY), exc.getMessage());
        assertTrue(exc.getMessage().contains(CommandParameterNames.PARAM_NAME_LONG_GENERATE_NEXT_VERIFYING_KEY), exc.getMessage());
        assertTrue(output.isEmpty());
        assertFalse(tmpDir.resolve(GENERATED_KEY_FILE_NAME).toFile().exists()); // nothing generated
    }

    private static Stream<Arguments> commandsWithoutKeySource() throws IOException, InvalidKeySpecException {
        var update = new UpdateDidLogCommand();
        update.didLogFile = writeStringToTempFile(buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE_JKS));
        setKeyMaterial(update); // the assertion/authentication keys alone do not denote a source of the signing key

        var deactivate = new DeactivateDidLogCommand();
        deactivate.didLogFile = writeStringToTempFile(buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE_JKS));

        var createPop = new CreateProofOfPossessionCommand();
        createPop.didLog = writeStringToTempFile(buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE));
        createPop.nonce = "my_nonce";
        createPop.kid = "did:webvh:SCID:example.com#my-assert-key-01";

        return Stream.of(
                Arguments.of(UpdateDidLogCommand.COMMAND_NAME, update, "Incomplete source"),
                Arguments.of(DeactivateDidLogCommand.COMMAND_NAME, deactivate, "No valid source"),
                Arguments.of(CreateProofOfPossessionCommand.COMMAND_NAME, createPop, "No valid source"));
    }

    @ParameterizedTest(name = "For command: {0}")
    @MethodSource("commandsWithoutKeySource")
    void run_withoutKeySource_throwsCommandException(String commandName, CommandBase command, String expectedMessageFragment, @TempDir Path tmpDir) {
        var exc = assertThrowsExactly(CommandException.class, () -> run(commandName, command, tmpDir)); // MUT

        assertTrue(exc.getMessage().contains(expectedMessageFragment), exc.getMessage());
        assertNull(exc.getCause());
        assertTrue(output.isEmpty());
    }

    @ParameterizedTest(name = "Generating the next key: {0}")
    @ValueSource(booleans = {true, false})
    void run_updateDidLogGeneratingKeyOverExistingOneWithoutForce_failsPrintingNoEntry(boolean generateNextKey, @TempDir Path tmpDir) throws Exception {
        new GeneratedKeyPairStore(tmpDir.toString()).storeKeysOnDisk(new EdDsaJcs2022VcDataIntegrityCryptographicSuite(), false);
        var existingKey = persistedKey(tmpDir);

        var command = new UpdateDidLogCommand();
        command.didLogFile = writeDidLog(tmpDir, buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE_JKS));
        command.signingKeyPemFile = new File(TEST_DATA_PATH_PREFIX + "private.pem");
        command.shouldGenerateNextVerifyingKeyPem = generateNextKey;
        command.shouldGenerateVerifyingKeyPem = !generateNextKey;
        setKeyMaterial(command); // essential

        var exc = assertThrowsExactly(CommandException.class, () -> run(UpdateDidLogCommand.COMMAND_NAME, command, tmpDir)); // MUT

        assertTrue(exc.getMessage().contains("The PEM file(s) exist(s) already"), exc.getMessage());
        assertTrue(output.isEmpty());
        assertEquals(existingKey, persistedKey(tmpDir)); // remains intact
    }

    @Test
    void run_createDidLogGeneratingNextKeyWithoutSigningKey_persistedKeyIsPrerotatedAndSignsNextUpdate(@TempDir Path tmpDir) throws Exception {
        var command = new CreateDidLogCommand();
        command.identifierRegistryUrl = URL.of(new URI(TEST_DID_URL), null);
        command.shouldGenerateNextVerifyingKeyPem = true;
        setKeyMaterial(command); // essential

        run(CreateDidLogCommand.COMMAND_NAME, command, tmpDir); // MUT

        var didLog = output.toString();
        var persistedKey = persistedKey(tmpDir);
        var didLogMeta = WebVerifiableHistoryDidLogMetaPeeker.peek(didLog);
        assertTrue(didLogMeta.isKeyPreRotationActivated());
        assertTrue(didLogMeta.isPreRotatedUpdateKey(persistedKey));
        assertFalse(didLogMeta.getParams().getUpdateKeys().contains(persistedKey));

        // CAUTION The persisted key is the only one left, as the initial signing key was deliberately never persisted
        var updateCommand = new UpdateDidLogCommand();
        updateCommand.didLogFile = writeDidLog(tmpDir, didLog);
        updateCommand.signingKeyPemFile = tmpDir.resolve(GENERATED_KEY_FILE_NAME).toFile();
        updateCommand.verifyingKeyPemFiles = Set.of(tmpDir.resolve("id_ed25519.pub").toFile()); // must match the pre-rotation key set by the initial entry
        setKeyMaterial(updateCommand); // essential
        output = new StringBuilder(); // reset output buffer

        run(UpdateDidLogCommand.COMMAND_NAME, updateCommand, tmpDir); // MUT

        didLogMeta = WebVerifiableHistoryDidLogMetaPeeker.peek(output.toString());
        assertEquals(2, didLogMeta.getLastVersionNumber());
        assertEquals(Set.of(persistedKey), didLogMeta.getParams().getUpdateKeys());
    }

    @Test
    void run_createDidLogGeneratingNextKeyWithSigningKey_suppliedKeySignsAndGeneratedKeyIsNextOnly(@TempDir Path tmpDir) throws Exception {
        var suppliedKey = TEST_CRYPTO_SUITE_JKS.getVerificationKeyMultibase(); // "private.pem" matches "myalias" key from "mykeystore.jks"
        var command = new CreateDidLogCommand();
        command.identifierRegistryUrl = URL.of(new URI(TEST_DID_URL), null);
        command.signingKeyPemFile = new File(TEST_DATA_PATH_PREFIX + "private.pem");
        command.shouldGenerateNextVerifyingKeyPem = true;
        setKeyMaterial(command); // essential

        run(CreateDidLogCommand.COMMAND_NAME, command, tmpDir); // MUT

        // REMINDER Peeking resolves the DID log, so the proof has been verified against the updateKeys at this point
        var didLogMeta = WebVerifiableHistoryDidLogMetaPeeker.peek(output.toString());
        assertEquals(Set.of(suppliedKey), didLogMeta.getParams().getUpdateKeys());
        assertNotEquals(suppliedKey, persistedKey(tmpDir));
        assertTrue(didLogMeta.isPreRotatedUpdateKey(persistedKey(tmpDir)));
        assertFalse(didLogMeta.isPreRotatedUpdateKey(suppliedKey));
    }

    @Test
    void run_createDidLogWithSuppliedKeys_printsThemAsUpdateKeysAndVerificationMethods(@TempDir Path tmpDir) throws Exception {
        var command = new CreateDidLogCommand();
        command.identifierRegistryUrl = URL.of(new URI(TEST_DID_URL), null);
        command.signingKeyPemFile = new File(TEST_DATA_PATH_PREFIX + "private.pem"); // matches "myalias" key from "mykeystore.jks"
        // CAUTION Beside the one matching the signing key, another one is required, as the former would be the update key by default
        command.verifyingKeyPemFiles = Set.of(new File(TEST_DATA_PATH_PREFIX + "public.pem"), TEST_KEY_FILES[0]);
        setKeyMaterial(command, "supplied-assert", "supplied-auth"); // essential

        run(CreateDidLogCommand.COMMAND_NAME, command, tmpDir); // MUT

        var didLogMeta = WebVerifiableHistoryDidLogMetaPeeker.peek(output.toString());
        assertEquals(Set.of(TEST_CRYPTO_SUITE_JKS.getVerificationKeyMultibase(), TEST_KEYS[0][1]), didLogMeta.getParams().getUpdateKeys());
        assertDidDocFeaturesKeys(didLogMeta.getDidDoc(), "supplied-assert", "supplied-auth");
    }

    @Test
    void run_createDidLogWithTdwMethodVersion_printsTdwDidLog(@TempDir Path tmpDir) throws Exception {
        var command = new CreateDidLogCommand();
        command.identifierRegistryUrl = URL.of(new URI(TEST_DID_URL), null);
        command.methodVersion = DidMethodEnum.TDW_0_3;
        setKeyMaterial(command); // essential

        run(CreateDidLogCommand.COMMAND_NAME, command, tmpDir); // MUT

        var didLogMeta = TdwDidLogMetaPeeker.peek(output.toString());
        assertEquals(1, didLogMeta.getLastVersionNumber());
        assertEquals(DidMethodEnum.TDW_0_3, didLogMeta.getParams().getDidMethodEnum());
    }

    private static Stream<Arguments> unverifiableProofs() throws DidLogMetaPeekerException {
        var didLog = buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE);
        return Stream.of(
                Arguments.of("signing key not matching kid", didLog, WebVerifiableHistoryDidLogMetaPeeker.peek(didLog).getDidDoc().getId() + "#my-assert-key-01", "auth-key-01"),
                Arguments.of("unparsable DID log", "this is not a DID log", "did:webvh:SCID:example.com#my-assert-key-01", "assert-key-01"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("unverifiableProofs")
    void run_createProofOfPossessionFailingSelfVerification_throwsCommandException(String description, String didLog, String kid, String signingKeyFileName, @TempDir Path tmpDir) throws Exception {
        var command = new CreateProofOfPossessionCommand();
        command.didLog = writeDidLog(tmpDir, didLog);
        command.nonce = "my_nonce";
        command.kid = kid;
        command.signingKeyPemFile = new File(TEST_DATA_PATH_PREFIX + signingKeyFileName);

        var exc = assertThrowsExactly(CommandException.class, () -> run(CreateProofOfPossessionCommand.COMMAND_NAME, command, tmpDir)); // MUT

        assertTrue(exc.getMessage().contains("Failed to verify generated proof"), exc.getMessage());
        assertInstanceOf(ProofOfPossessionVerifierException.class, exc.getCause());
        assertTrue(output.isEmpty()); // no JWT printed
    }
}
