package ch.admin.bj.swiyu.didtoolbox.cli;

import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.CreateProofOfPossessionCommand;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import ch.admin.bj.swiyu.didtoolbox.pop.ProofOfPossessionCreator;
import ch.admin.bj.swiyu.didtoolbox.pop.ProofOfPossessionCreatorException;
import ch.admin.bj.swiyu.didtoolbox.pop.ProofOfPossessionVerifier;
import ch.admin.bj.swiyu.didtoolbox.pop.ProofOfPossessionVerifierException;
import com.beust.jcommander.JCommander;
import com.nimbusds.jose.JOSEException;

import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.time.Duration;

/**
 * Runs the {@link CreateProofOfPossessionCommand}.
 */
final class CreateProofOfPossessionRunner extends AbstractCommandRunner<CreateProofOfPossessionCommand> {

    // Duration after which the JWT expires
    private static final Duration VALID_DURATION = Duration.ofDays(1);

    CreateProofOfPossessionRunner(JCommander jc, String commandName) {
        super(jc, commandName);
    }

    @Override
    void execute(CreateProofOfPossessionCommand command) throws IOException, ProofOfPossessionCreatorException, CommandException, GeneralSecurityException, JOSEException, VcDataIntegrityCryptographicSuiteException {
        var didLog = Files.readString(command.didLog.toPath());

        var signer = KeyMaterialLoaderFactory.from(command)
                .orElseThrow(() -> new CommandException("No valid source of signing P-256 key supplied. Use one of the relevant options to supply keys"))
                .loadProofOfPossessionSigner(command.kid);

        var proof = new ProofOfPossessionCreator(signer).create(command.nonce, VALID_DURATION);
        try {
            var verifier = new ProofOfPossessionVerifier(didLog);
            verifier.verify(proof, command.nonce);
        } catch (ProofOfPossessionVerifierException e) {
            throw new CommandException("Failed to verify generated proof: %s".formatted(e.getLocalizedMessage()), e);
        }

        println(proof.serialize());
    }
}
