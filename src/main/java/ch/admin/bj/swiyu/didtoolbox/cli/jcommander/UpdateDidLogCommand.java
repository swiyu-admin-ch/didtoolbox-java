package ch.admin.bj.swiyu.didtoolbox.cli.jcommander;

import ch.admin.bj.swiyu.didtoolbox.cli.CommandException;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.converter.DidLogFileParameterConverter;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.validator.CommandParametersValidator;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.validator.DidLogFileParameterValidator;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogUpdaterContext;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogUpdaterStrategyException;
import ch.admin.bj.swiyu.didtoolbox.did.model.NextKeyHashesDidMethodParameter;
import ch.admin.bj.swiyu.didtoolbox.did.model.NextKeyHashesDidMethodParameterException;
import ch.admin.bj.swiyu.didtoolbox.did.model.UpdateKeysDidMethodParameter;
import ch.admin.bj.swiyu.didtoolbox.did.model.UpdateKeysDidMethodParameterException;
import ch.admin.bj.swiyu.didtoolbox.did.model.VerificationMethodException;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.beust.jcommander.Parameters;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import static ch.admin.bj.swiyu.didtoolbox.cli.jcommander.CommandParameterNames.PARAM_NAME_LONG_GENERATE_NEW_VERIFYING_KEY;
import static ch.admin.bj.swiyu.didtoolbox.cli.jcommander.CommandParameterNames.PARAM_NAME_LONG_GENERATE_NEXT_VERIFYING_KEY;
import static ch.admin.bj.swiyu.didtoolbox.cli.jcommander.CommandParameterNames.PARAM_NAME_SHORT_GENERATE_NEW_VERIFYING_KEY;

@Parameters(
        commandNames = {UpdateDidLogCommand.COMMAND_NAME},
        commandDescription = "Update a DID log by replacing the existing verification material in DID document. " +
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
public class UpdateDidLogCommand extends KeyMaterialDidLogCommand {

    final public static String COMMAND_NAME = "update";

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_DID_LOG_FILE, CommandParameterNames.PARAM_NAME_SHORT_DID_LOG_FILE},
            description = "The file containing a valid DID log to update",
            converter = DidLogFileParameterConverter.class,
            validateWith = DidLogFileParameterValidator.class,
            required = true)
    public File didLogFile;

    @Parameter(names = {PARAM_NAME_LONG_GENERATE_NEW_VERIFYING_KEY, PARAM_NAME_SHORT_GENERATE_NEW_VERIFYING_KEY},
            description = "Requires the signing key pem file flag (-s). Generates a new ed25519 key pair to be used as 'pre-rotation' key. The generated key pair is stored in the `.didtoolbox` directory. CAUTION: using `-f` can override existing keys in the directory, make sure to back them up. Cannot be used together with the generate update key next flag ('-gw)")
    public boolean shouldGenerateVerifyingKeyPem;

    @Override
    protected void execute(CommandContext context) throws CommandException, VerificationMethodException, IOException, VcDataIntegrityCryptographicSuiteException, UpdateKeysDidMethodParameterException, NextKeyHashesDidMethodParameterException, DidLogUpdaterStrategyException {
        var didLogMeta = fetchDidLogMeta(didLogFile);

        // CAUTION At this point, it should be all in place to update to be able to update the supplied DID log

        var outputDir = context.keyPairStore().getOutputDir().toPath();
        var assertionMethods = getAssertionMethods(outputDir);
        var authentications = getAuthentications(outputDir);

        if (authentications.isEmpty() && assertionMethods.isEmpty()) {
            throw new CommandException("No update will take place as no verification material is supplied whatsoever");
        }

        if (shouldGenerateNextVerifyingKeyPem || shouldGenerateVerifyingKeyPem) {
            if (shouldGenerateNextVerifyingKeyPem && shouldGenerateVerifyingKeyPem) {
                throw new ParameterException("Not allowed to use the both flags ('%s', '%s' together".formatted(PARAM_NAME_LONG_GENERATE_NEW_VERIFYING_KEY, PARAM_NAME_LONG_GENERATE_NEXT_VERIFYING_KEY));
            }

            if (shouldGenerateNextVerifyingKeyPem) {
                context.keyPairStore().generateAndSaveNewKey(forceOverwrite, nextVerifyingKeyPemFiles);
            } else {
                context.keyPairStore().generateAndSaveNewKey(forceOverwrite, verifyingKeyPemFiles);
            }
        }

        var cryptoSuite = keyMaterialLoader()
                .orElseThrow(() -> new CommandException("Incomplete source of the (signing/verifying) ed25519 keys supplied. Use one of the relevant options to supply keys"))
                .loadCryptographicSuite();

        if (didLogMeta.isKeyPreRotationActivated() && !didLogMeta.isPreRotatedUpdateKey(cryptoSuite.getVerificationKeyMultibase())) {
            throw new CommandException("Illegal signing (private) ed25519 key supplied");
        }

        // CAUTION At this point, the methodVersion var of type DidMethodEnum MUST be non-null already
        context.println(Files.readString(didLogFile.toPath()).trim() + System.lineSeparator() +
                DidLogUpdaterContext.builder(didLogMeta.getParams().getDidMethodEnum(), cryptoSuite)
                        .assertionMethods(assertionMethods)
                        .authentications(authentications)
                        // Instead of calling deprecated .updateKeys(verifyingKeyPemFiles)
                        .updateKeysDidMethodParameter(UpdateKeysDidMethodParameter.of(verifyingKeyPemFiles))
                        // Instead of calling deprecated .nextKeys(nextVerifyingKeyPemFiles)
                        .nextKeyHashesDidMethodParameter(NextKeyHashesDidMethodParameter.of(nextVerifyingKeyPemFiles))
                        .build()
                        .update(didLogFile));
    }
}
