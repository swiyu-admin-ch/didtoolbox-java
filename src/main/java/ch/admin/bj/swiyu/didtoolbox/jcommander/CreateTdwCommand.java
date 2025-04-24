package ch.admin.bj.swiyu.didtoolbox.jcommander;

import ch.admin.bj.swiyu.didtoolbox.securosys.primus.PrimusKeyStoreLoader;
import com.beust.jcommander.*;

import java.io.File;
import java.net.URL;
import java.util.List;
import java.util.Set;

@Parameters(
        commandNames = {"create"},
        commandDescription = "Create a did:tdw DID and sign the initial DID log entry with the provided private key. " +
                "To supply a signing/verifying key pair, always rely on one of the three available command parameter sets exclusively, " +
                "each of then denoting a whole another source of such key material: " +
                "PEM files, a Java KeyStore (PKCS12) or a Securosys Primus (HSM) connection. " +
                "In case of a Securosys Primus (HSM) connection, the required JCE provider (JAR) library " +
                "(primusX-java8.jar or primusX-java11.jar) is expected to be stored on the system alongside the DID-Toolbox, " +
                "more specifically in the lib subdirectory, e.g. as lib/primusX-java11.jar",
        // Validate the value for all parameters (currently not really required):
        parametersValidators = {TdwCommandParametersValidator.class}
)
public class CreateTdwCommand {

    final public static String DEFAULT_METHOD_VERSION = "did:tdw:0.3";
    @Parameter(names = {"--help", "-h"},
            description = "Display help for the DID toolbox 'create' command",
            help = true)
    public boolean help;

    @Parameter(names = {"--force-overwrite", "-f"},
            description = "Overwrite existing PEM key files, if any")
    public boolean forceOverwrite;

    @Parameter(names = {"--identifier-registry-url", "-u"},
            description = "A HTTP(S) DID URL (to did.jsonl) to create TDW DID log for",
            required = true,
            converter = IdentifierRegistryUrlParameterConverter.class,
            validateWith = IdentifierRegistryUrlParameterValidator.class)
    public URL identifierRegistryUrl;

    @Parameter(names = {"--method-version", "-m"},
            description = "Defines the did:tdw specification version to use when generating a DID log. Currently supported is only '" + DEFAULT_METHOD_VERSION + "'",
            defaultValueDescription = DEFAULT_METHOD_VERSION)
    //,required = true)
    public String methodVersion;

    @Parameter(names = {"--signing-key-file", "-s"},
            description = "The ed25519 private key file corresponding to the public key, required to sign and output the initial DID log entry. In PEM Format. " +
                    "This CLI parameter cannot be used in conjunction with any of --jks-* or --primus-* CLI parameters",
            converter = PemFileParameterConverter.class,
            validateWith = PemFileParameterValidator.class)
    public File signingKeyPemFile;

    @Parameter(names = {"--verifying-key-files", "-v"},
            description = "The ed25519 public key file(s) for the DID Document’s verification method. One should match the ed25519 private key supplied via -s option. In PEM format. " +
                    "This CLI parameter cannot be used in conjunction with any of --jks-* or --primus-* CLI parameters",
            listConverter = PemFileParameterListConverter.class,
            //converter = PemFileParameterConverter.class,
            validateWith = PemFileParameterValidator.class,
            variableArity = true)
    public Set<File> verifyingKeyPemFiles;
    /*
    static class OutputDirParameterConverter implements IStringConverter<File> {
        @Override
        public File convert(String value) {
            return new File(value);
        }
    }

    public static class OutputDirParameterValidator implements IParameterValidator {
        @Override
        public void validate(String name, String value) throws ParameterException {
            File dir = new File(value);
            if (dir.exists() && !dir.isDirectory()) {
                throw new ParameterException("Parameter " + name + " should be a directory, not a file (found " + value + ")");
            }
        }
    }

    @Parameter(names = {"--key-pair-output-dir", "-o"},
            description = "The directory to store the generated key pair (both in PEM Format), in case no external keys are supplied. Otherwise, ignored",
            converter = OutputDirParameterConverter.class,
            validateWith = OutputDirParameterValidator.class)
    File outputDir;
     */
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
