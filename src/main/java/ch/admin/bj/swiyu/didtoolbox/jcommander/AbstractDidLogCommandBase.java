package ch.admin.bj.swiyu.didtoolbox.jcommander;

import ch.admin.bj.swiyu.didtoolbox.jcommander.validator.JksFileParameterValidator;
import ch.admin.bj.swiyu.didtoolbox.jcommander.validator.PemFileParameterValidator;
import ch.admin.bj.swiyu.didtoolbox.jcommander.validator.PrimusCredentialsFileParameterValidator;
import ch.admin.bj.swiyu.didtoolbox.securosys.primus.PrimusKeyStoreLoader;
import com.beust.jcommander.Parameter;

import java.io.File;

/**
 * The base class for all Command classes in the package that focus on DID logs.
 */
abstract class AbstractDidLogCommandBase extends AbstractCommandBase {

    @Override
    abstract String getCommandName();

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_SIGNING_KEY_FILE, CommandParameterNames.PARAM_NAME_SHORT_SIGNING_KEY_FILE},
            description = "The ed25519 private key file required for signing a DID log entry or a PoP JWT. In PEM Format. " +
                    "This CLI parameter cannot be used in conjunction with any of --jks-* or --primus-* CLI parameters",
            converter = PemFileParameterConverter.class,
            validateWith = PemFileParameterValidator.class)
    public File signingKeyPemFile;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_JKS_FILE, CommandParameterNames.PARAM_NAME_SHORT_JKS_FILE},
            description = "Java KeyStore (PKCS12) file to read the (signing/verifying) keys from. " +
                    "This CLI parameter should always be used exclusively alongside all the other --jks-* CLI parameters",
            converter = JksFileParameterConverter.class,
            validateWith = JksFileParameterValidator.class)
    public File jksFile;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_JKS_PASSWORD},
            description = "Java KeyStore password used to check the integrity of the keystore, the password used to unlock the keystore. " +
                    "This CLI parameter should always be used exclusively alongside all the other --jks-* CLI parameters",
            password = true)
    public String jksPassword;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_JKS_ALIAS},
            description = "Java KeyStore alias name of the entry to process. " +
                    "This CLI parameter should always be used exclusively alongside all the other --jks-* CLI parameters")
    public String jksAlias;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_PRIMUS_CREDENTIALS, CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_CREDENTIALS},
            description = "A safely stored credentials file required when using (signing/verifying) keys available in the Securosys Primus (HSM) Keystore. " +
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
            description = "An alias the (signing/verifying) key pair (stored in the Securosys Primus (HSM) Keystore) is associated with. " +
                    "This CLI parameter should always be used exclusively alongside all the other --primus-* CLI parameters, related to Securosys Primus (HSM)")
    public String primusKeyAlias;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD},
            description = "An optional password required for recovering the (signing/verifying) key pair (stored in Securosys Primus (HSM) Keystore). " +
                    "This CLI parameter should always be used exclusively alongside all the other --primus-* CLI parameters, related to Securosys Primus (HSM)",
            password = true)
    public String primusKeyPassword;
}
