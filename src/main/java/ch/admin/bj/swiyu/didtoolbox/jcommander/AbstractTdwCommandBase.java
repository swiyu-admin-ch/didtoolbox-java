package ch.admin.bj.swiyu.didtoolbox.jcommander;

import ch.admin.bj.swiyu.didtoolbox.securosys.primus.PrimusKeyStoreLoader;
import com.beust.jcommander.Parameter;

import java.io.File;

/**
 * The base class for all Command classes in the package.
 */
abstract class AbstractTdwCommandBase {

    @Parameter(names = {"--signing-key-file", "-s"},
            description = "The ed25519 private key file corresponding to the public key, required to sign and output the initial DID log entry. In PEM Format. " +
                    "This CLI parameter cannot be used in conjunction with any of --jks-* or --primus-* CLI parameters",
            converter = PemFileParameterConverter.class,
            validateWith = PemFileParameterValidator.class)
    public File signingKeyPemFile;

    @Parameter(names = {"--jks-file", "-j"},
            description = "Java KeyStore (PKCS12) file to read the (signing/verifying) keys from. " +
                    "This CLI parameter should always be used exclusively alongside all the other --jks-* CLI parameters",
            converter = JksFileParameterConverter.class,
            validateWith = JksFileParameterValidator.class)
    public File jksFile;

    @Parameter(names = {"--jks-password"},
            description = "Java KeyStore password used to check the integrity of the keystore, the password used to unlock the keystore. " +
                    "This CLI parameter should always be used exclusively alongside all the other --jks-* CLI parameters",
            password = true)
    public String jksPassword;

    @Parameter(names = {"--jks-alias"},
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
