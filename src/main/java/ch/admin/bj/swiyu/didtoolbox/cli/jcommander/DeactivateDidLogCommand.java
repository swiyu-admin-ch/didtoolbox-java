package ch.admin.bj.swiyu.didtoolbox.cli.jcommander;

import ch.admin.bj.swiyu.didtoolbox.cli.CommandException;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.converter.DidLogFileParameterConverter;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.validator.CommandParametersValidator;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.validator.DidLogFileParameterValidator;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogDeactivatorContext;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogDeactivatorStrategyException;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

@Parameters(
        commandNames = {DeactivateDidLogCommand.COMMAND_NAME},
        commandDescription = "Deactivate (revoke) a DID log. " +
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
public class DeactivateDidLogCommand extends DidLogCommandBase {

    final public static String COMMAND_NAME = "deactivate";

    @Parameter(names = {"--did-log-file", "-d"},
            description = "The file containing a valid DID log to deactivate",
            converter = DidLogFileParameterConverter.class,
            validateWith = DidLogFileParameterValidator.class,
            required = true)
    public File didLogFile;

    @Override
    protected void execute(CommandContext context) throws CommandException, VcDataIntegrityCryptographicSuiteException, IOException, DidLogDeactivatorStrategyException {
        var didLogMeta = fetchDidLogMeta(didLogFile);

        var cryptoSuite = keyMaterialLoader()
                .orElseThrow(() -> new CommandException("No valid source of signing/verifying ed25519 keys supplied. Use one of the relevant options to supply keys"))
                .loadCryptographicSuite();

        // CAUTION Trimming the existing DID log prevents ending up having multiple line separators in between (after appending the new entry)
        context.println(Files.readString(didLogFile.toPath()).trim() + System.lineSeparator() +
                DidLogDeactivatorContext.builder(didLogMeta.getParams().getDidMethodEnum(), cryptoSuite)
                        .build()
                        .deactivate(didLogFile));
    }
}
