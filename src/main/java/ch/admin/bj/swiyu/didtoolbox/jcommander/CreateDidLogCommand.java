package ch.admin.bj.swiyu.didtoolbox.jcommander;

import ch.admin.bj.swiyu.didtoolbox.jcommander.validator.CommandParametersValidator;
import ch.admin.bj.swiyu.didtoolbox.jcommander.validator.IdentifierRegistryUrlParameterValidator;
import ch.admin.bj.swiyu.didtoolbox.model.DidMethodEnum;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

import java.net.URL;

@Parameters(
        commandNames = {CreateDidLogCommand.COMMAND_NAME},
        commandDescription = "Create a DID and sign the initial DID log entry with the provided private key. " +
                "To supply a signing/verifying key pair, always rely on one of the three available command parameter sets exclusively, " +
                "each of then denoting a whole another source of such key material: " +
                "PEM files, a Java KeyStore (PKCS12) or a Securosys Primus (HSM) connection. " +
                "In case of a Securosys Primus (HSM) connection, the required JCE provider (JAR) library " +
                "(primusX-java8.jar or primusX-java11.jar) is by-convention expected to be stored on the system alongside the DID-Toolbox " +
                "in the lib subdirectory (e.g. as lib/primusX-java11.jar). " +
                "Alternatively, you may also use -Xbootclasspath/a:directories|zip|JAR-files option of the java command for the purpose",
        // Validate the value for all parameters (currently not really required):
        parametersValidators = {CommandParametersValidator.class}
)
public class CreateDidLogCommand extends AbstractKeyMaterialTdwCommand {

    final public static String COMMAND_NAME = "create";

    final public static DidMethodEnum DEFAULT_METHOD_VERSION = DidMethodEnum.WEBVH_1_0;

    @Parameter(names = {"--force-overwrite", "-f"},
            description = "Overwrite existing PEM key files, if any")
    public boolean forceOverwrite;

    @Parameter(names = {"--identifier-registry-url", "-u"},
            description = "A HTTP(S) DID URL (to did.jsonl) to create a DID log for",
            required = true,
            converter = IdentifierRegistryUrlParameterConverter.class,
            validateWith = IdentifierRegistryUrlParameterValidator.class)
    public URL identifierRegistryUrl;

    @Parameter(names = {"--method-version", "-m"},
            description = "Defines the DID method specification version to use when generating a DID log. Case-insensitive. Valid values: '" + DidMethodEnum.TDW_0_3_STRING + "', '" + DidMethodEnum.WEBVH_1_0_STRING + "'",
            defaultValueDescription = DidMethodEnum.WEBVH_1_0_STRING)
    //,required = true)
    public String methodVersion;
}
