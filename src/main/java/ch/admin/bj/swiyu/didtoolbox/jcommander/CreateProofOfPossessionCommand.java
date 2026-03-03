package ch.admin.bj.swiyu.didtoolbox.jcommander;

import ch.admin.bj.swiyu.didtoolbox.jcommander.validator.CommandParametersValidator;
import ch.admin.bj.swiyu.didtoolbox.jcommander.validator.PemFileParameterValidator;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

import java.io.File;

@Parameters(
        commandNames = {CreateProofOfPossessionCommand.COMMAND_NAME},
        commandDescription = "Create a proof of possession JWT signed with the provided private key that expires after 24 hours. ",
        parametersValidators = {CommandParametersValidator.class}
)
public class CreateProofOfPossessionCommand extends AbstractCommandBase {
    final public static String COMMAND_NAME = "create-pop";

    @Override
    String getCommandName(){
        return COMMAND_NAME;
    }

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_NONCE, CommandParameterNames.PARAM_NAME_SHORT_NONCE},
            description = "Possession which will be proven by the JWT",
            required = true)
    public String nonce;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_DID_LOG_FILE, CommandParameterNames.PARAM_NAME_SHORT_DID_LOG_FILE},
            description = "The file containing a valid DID log to update",
            required = true)
    public File didLog;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_KID, CommandParameterNames.PARAM_NAME_SHORT_KID},
            description = "KID of the key within the DID log to use.",
            required = true)
    public String kid;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_SIGNING_KEY_FILE, CommandParameterNames.PARAM_NAME_SHORT_SIGNING_KEY_FILE},
            description = "An EC P-256 private key file matching the specified key within the DID log",
            converter = PemFileParameterConverter.class,
            validateWith = PemFileParameterValidator.class,
            required = true)
    public File signingKeyPemFile;
}
