package ch.admin.bj.swiyu.didtoolbox.jcommander;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

import java.io.File;
import java.net.URL;
import java.util.List;
import java.util.Set;

@Parameters(
        commandNames = {CreateTdwCommand.COMMAND_NAME},
        commandDescription = "Create a did:tdw DID and sign the initial DID log entry with the provided private key. " +
                "To supply a signing/verifying key pair, always rely on one of the three available command parameter sets exclusively, " +
                "each of then denoting a whole another source of such key material: " +
                "PEM files, a Java KeyStore (PKCS12) or a Securosys Primus (HSM) connection. " +
                "In case of a Securosys Primus (HSM) connection, the required JCE provider (JAR) library " +
                "(primusX-java8.jar or primusX-java11.jar) is expected to be stored on the system alongside the DID-Toolbox " +
                "in the lib subdirectory (e.g. as lib/primusX-java11.jar)",
        // Validate the value for all parameters (currently not really required):
        parametersValidators = {TdwCommandParametersValidator.class}
)
public class CreateTdwCommand extends AbstractTdwCommandBase {

    final public static String COMMAND_NAME = "create";

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
