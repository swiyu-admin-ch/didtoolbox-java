package ch.admin.bj.swiyu.didtoolbox.jcommander;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

import java.io.File;

@Parameters(
        commandNames = {CreateProofOfPossessionCommand.COMMAND_NAME},
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
            description = "Possession which will be proven by the JWT",
            required = true)
    public String nonce;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_VERIFYING_KEY_FILE, CommandParameterNames.PARAM_NAME_SHORT_VERIFYING_KEY_FILE},
            description = "An ed25519 public key file matching the supplied ed25519 private key file, required for signing the PoP JWT. In PEM format. " +
                    "This CLI parameter cannot be used in conjunction with any of --jks-* or --primus-* CLI parameters",
            converter = PemFileParameterConverter.class,
            validateWith = PemFileParameterValidator.class,
            variableArity = true)
    public File verifyingKeyPemFile;
}
