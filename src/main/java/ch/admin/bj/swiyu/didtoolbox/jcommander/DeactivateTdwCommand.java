package ch.admin.bj.swiyu.didtoolbox.jcommander;

import java.io.File;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

@Parameters(
        commandNames = {DeactivateTdwCommand.COMMAND_NAME},
        commandDescription = "Deactivate (revoke) a did:tdw DID log. " +
                "To supply a signing/verifying key pair, always rely on one of the three available command parameter sets exclusively, " +
                "each of then denoting a whole another source of such key material: " +
                "PEM files, a Java KeyStore (PKCS12) or a Securosys Primus (HSM) connection. " +
                "In case of a Securosys Primus (HSM) connection, the required JCE provider (JAR) library " +
                "(primusX-java8.jar or primusX-java11.jar) is expected to be stored on the system alongside the DID-Toolbox " +
                "in the lib subdirectory (e.g. as lib/primusX-java11.jar)",
        // Validate the value for all parameters (currently not really required):
        parametersValidators = {TdwCommandParametersValidator.class}
)
public class DeactivateTdwCommand extends AbstractTdwCommandBase {

    final public static String COMMAND_NAME = "deactivate";

    @Parameter(names = {"--help", "-h"},
            description = "Display help for the DID toolbox 'deactivate' command",
            help = true)
    public boolean help;

    @Parameter(names = {"--did-log-file", "-d"},
            description = "The file containing a valid did:tdw DID log to deactivate",
            converter = DidLogFileParameterConverter.class,
            validateWith = DidLogFileParameterValidator.class,
            required = true)
    public File didLogFile;
}
