package ch.admin.bj.swiyu.didtoolbox.jcommander;

import ch.admin.bj.swiyu.didtoolbox.jcommander.validator.CommandParametersValidator;
import ch.admin.bj.swiyu.didtoolbox.jcommander.validator.PemFileParameterValidator;
import ch.admin.bj.swiyu.didtoolbox.jcommander.validator.PrimusCredentialsFileParameterValidator;
import ch.admin.bj.swiyu.didtoolbox.securosys.primus.PrimusKeyStoreLoader;
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
    String getCommandName() {
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
            required = false)
    public File signingKeyPemFile;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_PRIMUS_CREDENTIALS, CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_CREDENTIALS},
            description = "A safely stored credentials file required when using private keys available in the Securosys Primus (HSM) Keystore. " +
                    "It should feature a quartet of the following properties: " +
                    "securosys_primus_host, securosys_primus_port, securosys_primus_user and securosys_primus_password. " +
                    "Any credential missing in this file will simply fallback to its system environment counterpart (if set) - the relevant envvars in this case are: " +
                    "SECUROSYS_PRIMUS_HOST, SECUROSYS_PRIMUS_PORT, SECUROSYS_PRIMUS_USER and SECUROSYS_PRIMUS_PASSWORD. " +
                    "This CLI parameter should always be used exclusively alongside all the other --primus-* CLI parameters, related to Securosys Primus (HSM)",
            converter = PrimusCredentialsFileParameterConverter.class,
            validateWith = PrimusCredentialsFileParameterValidator.class
    )
    public PrimusKeyStoreLoader securosysPrimusKeyStoreLoader;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS},
        description = "An alias the key pair (stored in the Securosys Primus (HSM) Keystore) is associated with. " +
            "This CLI parameter should always be used exclusively alongside all the other --primus-* CLI parameters, related to Securosys Primus (HSM)")
    public String primusKeyAlias;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD},
            description = "An optional password required for recovering the key pair (stored in Securosys Primus (HSM) Keystore). " +
                    "This CLI parameter should always be used exclusively alongside all the other --primus-* CLI parameters, related to Securosys Primus (HSM)",
            password = true)
    public String primusKeyPassword;
}
