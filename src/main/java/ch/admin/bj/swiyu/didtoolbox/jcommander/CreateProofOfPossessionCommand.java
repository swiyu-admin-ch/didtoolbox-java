package ch.admin.bj.swiyu.didtoolbox.jcommander;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

import java.io.File;

@Parameters(
      commandNames = {CreateProofOfPossessionCommand.COMMAND_NAME} ,
        commandDescription = "Create a proof of possession JWT signed with the provided private key that expires after 24 hours. " +
                "To supply a signing/verifying key pair, always rely on one of the three available command parameter sets exclusively, " +
                "each of then denoting a whole another source of such key material: " +
                "PEM files, a Java KeyStore (PKCS12) or a Securosys Primus (HSM) connection. " +
                "In case of a Securosys Primus (HSM) connection, the required JCE provider (JAR) library " +
                "(primusX-java8.jar or primusX-java11.jar) is by-convention expected to be stored on the system alongside the DID-Toolbox " +
                "in the lib subdirectory (e.g. as lib/primusX-java11.jar). " +
                "Alternatively, you may also use -Xbootclasspath/a:directories|zip|JAR-files option of the java command for the purpose",
        parametersValidators = {TdwCommandParametersValidator.class}
)
public class CreateProofOfPossessionCommand extends AbstractTdwCommandBase {
    final public static String COMMAND_NAME = "create-pop";

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_NONCE, CommandParameterNames.PARAM_NAME_SHORT_NONCE},
        description = "Possession which will be proven by the jwt",
        required = true)
    public String nonce;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_DID_LOG_FILE, CommandParameterNames.PARAM_NAME_SHORT_DID_LOG_FILE},
            description = "The file containing a valid did:tdw DID log to verify the JWT",
            converter = DidLogFileParameterConverter.class,
            validateWith = DidLogFileParameterValidator.class,
            required = true)
    public File didLogFile;
}
