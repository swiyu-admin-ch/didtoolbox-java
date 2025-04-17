package ch.admin.bj.swiyu.didtoolbox.jcommander;

import ch.admin.bj.swiyu.didtoolbox.securosys.primus.PrimusKeyStoreLoader;
import com.beust.jcommander.*;

import java.io.File;
import java.util.List;
import java.util.Set;

@Parameters(
        commandNames = {"update"},
        commandDescription = "Update a did:tdw DID log by replacing the existing verification material in DID document",
        // Validate the value for all parameters (currently not really required):
        parametersValidators = {TdwCommandParametersValidator.class}
)
public class UpdateTdwCommand {

    @Parameter(names = {"--help", "-h"},
            description = "Display help for the DID toolbox 'update' command",
            help = true)
    public boolean help;

    @Parameter(names = {"--did-log-file", "-d"},
            description = "The file containing a valid did:tdw DID log to update",
            converter = DidLogFileParameterConverter.class,
            validateWith = DidLogFileParameterValidator.class,
            required = true)
    public File didLogFile;

    @Parameter(names = {"--signing-key-file", "-s"},
            description = "The ed25519 private key file corresponding to the public key, required to sign and output the updated DID log entry. In PEM Format",
            converter = PemFileParameterConverter.class,
            validateWith = PemFileParameterValidator.class)
    public File signingKeyPemFile;

    @Parameter(names = {"--verifying-key-files", "-v"},
            description = "The ed25519 public key file(s) for the DID Document’s verification method. In PEM format",
            listConverter = PemFileParameterListConverter.class,
            //converter = PemFileParameterConverter.class,
            validateWith = PemFileParameterValidator.class,
            variableArity = true)
    public Set<File> verifyingKeyPemFiles;

    @Parameter(names = {"--jks-file", "-j"},
            description = "Java KeyStore (PKCS12) file to read the (signing/verifying) keys from",
            converter = JksFileParameterConverter.class,
            validateWith = JksFileParameterValidator.class)
    public File jksFile;

    @Parameter(names = {"--jks-password"},
            description = "Java KeyStore password used to check the integrity of the keystore, the password used to unlock the keystore",
            password = true)
    public String jksPassword;

    @Parameter(names = {"--jks-alias"},
            description = "Java KeyStore alias")
    public String jksAlias;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE, CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE},
            description = "Securosys Primus Keystore credentials file",
            converter = PrimusCredentialsFileParameterConverter.class,
            validateWith = PrimusCredentialsFileParameterValidator.class
    )
    public PrimusKeyStoreLoader securosysPrimusKeyStoreLoader;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS},
            description = "Securosys Primus Keystore alias the key is associated with")
    public String primusKeyAlias;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD, CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_PASSWORD},
            description = "Securosys Primus Keystore password for recovering the key")
    public String primusKeyPassword;

    @Parameter(names = {"--assert", "-a"},
            description = "An assertion method (comma-separated) parameters: a key name as well as a PEM file containing EC P-256 public/verifying key",
            listConverter = VerificationMethodParametersConverter.class,
            validateWith = VerificationMethodKeyParametersValidator.class,
            variableArity = true)
    public List<VerificationMethodParameters> assertionMethodKeys;

    @Parameter(names = {"--auth", "-t"},
            description = "An authentication method (comma-separated) parameters: a key name as well as a PEM file containing EC P-256 public/verifying key",
            listConverter = VerificationMethodParametersConverter.class,
            validateWith = VerificationMethodKeyParametersValidator.class,
            variableArity = true)
    public List<VerificationMethodParameters> authenticationKeys;
}
