package ch.admin.bj.swiyu.didtoolbox.cli;

import ch.admin.bj.swiyu.didtoolbox.pop.ProofOfPossessionVerifierException;
import ch.admin.bj.swiyu.didtoolbox.pop.ProofOfPossessionVerifier;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.VerifyProofOfPossessionCommand;
import com.beust.jcommander.JCommander;

import java.io.IOException;
import java.nio.file.Files;

/**
 * Runs the {@link VerifyProofOfPossessionCommand}.
 */
final class VerifyProofOfPossessionRunner extends AbstractCommandRunner<VerifyProofOfPossessionCommand> {

    VerifyProofOfPossessionRunner(JCommander jc, String commandName) {
        super(jc, commandName);
    }

    @Override
    void execute(VerifyProofOfPossessionCommand command) throws IOException, CommandException {
        var didLog = Files.readString(command.didLogFile.toPath());

        try {
            new ProofOfPossessionVerifier(didLog)
                    .verify(command.jwt, command.nonce);
            println("Provided JWT is valid.");
        } catch (ProofOfPossessionVerifierException e) {
            throw new CommandException("Provided JWT is invalid: " + e.getLocalizedMessage(), e);
        }
    }
}
