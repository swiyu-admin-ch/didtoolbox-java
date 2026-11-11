package ch.admin.bj.swiyu.didtoolbox.cli.jcommander;

import ch.admin.bj.swiyu.didtoolbox.cli.CommandException;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.converter.DidLogFileParameterConverter;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.converter.JWTParameterConverter;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.validator.CommandParametersValidator;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.validator.DidLogFileParameterValidator;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.validator.JWTParameterValidator;
import ch.admin.bj.swiyu.didtoolbox.pop.ProofOfPossessionVerifier;
import ch.admin.bj.swiyu.didtoolbox.pop.ProofOfPossessionVerifierException;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import com.nimbusds.jwt.SignedJWT;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

@Parameters(
        commandNames = {VerifyProofOfPossessionCommand.COMMAND_NAME},
        commandDescription = "Verifies the validity of the provided proof of possession JWT.",
        parametersValidators = {CommandParametersValidator.class}
)
public class VerifyProofOfPossessionCommand extends CommandBase {

    public final static String COMMAND_NAME = "verify-pop";

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_NONCE, CommandParameterNames.PARAM_NAME_SHORT_NONCE},
            description = "Text representation of the possession to be included in the proof",
            required = true)
    public String nonce;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_DID_LOG_FILE, CommandParameterNames.PARAM_NAME_SHORT_DID_LOG_FILE},
            description = "The file containing a valid DID log of the owner.",
            converter = DidLogFileParameterConverter.class,
            validateWith = DidLogFileParameterValidator.class,
            required = true)
    public File didLogFile;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_JWT, CommandParameterNames.PARAM_NAME_SHORT_JWT},
            description = "JWT to be verified",
            converter = JWTParameterConverter.class,
            validateWith = JWTParameterValidator.class,
            required = true)
    public SignedJWT jwt;

    @Override
    protected void execute(CommandContext context) throws IOException, CommandException {
        var didLog = Files.readString(didLogFile.toPath());

        try {
            new ProofOfPossessionVerifier(didLog)
                    .verify(jwt, nonce);
            context.println("Provided JWT is valid.");
        } catch (ProofOfPossessionVerifierException e) {
            throw new CommandException("Provided JWT is invalid: " + e.getLocalizedMessage(), e);
        }
    }
}
