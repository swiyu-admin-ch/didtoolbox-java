package ch.admin.bj.swiyu.didtoolbox.cli.jcommander;

import ch.admin.bj.swiyu.didtoolbox.cli.CommandException;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.converter.DidMethodParameterConverter;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.converter.IdentifierRegistryUrlParameterConverter;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.validator.CommandParametersValidator;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.validator.DidMethodParameterValidator;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.validator.IdentifierRegistryUrlParameterValidator;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogCreatorContext;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogCreatorStrategyException;
import ch.admin.bj.swiyu.didtoolbox.did.model.DidMethodEnum;
import ch.admin.bj.swiyu.didtoolbox.did.model.NextKeyHashesDidMethodParameter;
import ch.admin.bj.swiyu.didtoolbox.did.model.NextKeyHashesDidMethodParameterException;
import ch.admin.bj.swiyu.didtoolbox.did.model.UpdateKeysDidMethodParameter;
import ch.admin.bj.swiyu.didtoolbox.did.model.UpdateKeysDidMethodParameterException;
import ch.admin.bj.swiyu.didtoolbox.did.model.VerificationMethodException;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

import java.io.IOException;
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
public class CreateDidLogCommand extends KeyMaterialDidLogCommand {

    public static final String COMMAND_NAME = "create";

    public static final DidMethodEnum DEFAULT_METHOD_VERSION = DidMethodEnum.WEBVH_1_0;

    @Parameter(names = {"--identifier-registry-url", "-u"},
            description = "A HTTP(S) DID URL (to did.jsonl) to create a DID log for",
            required = true,
            converter = IdentifierRegistryUrlParameterConverter.class,
            validateWith = IdentifierRegistryUrlParameterValidator.class)
    public URL identifierRegistryUrl;

    @Parameter(names = {"--method-version", "-m"},
            description = "Defines the DID method specification version to use when generating a DID log. Case-insensitive. Valid values: '" + DidMethodEnum.TDW_0_3_STRING + "', '" + DidMethodEnum.WEBVH_1_0_STRING + "'",
            converter = DidMethodParameterConverter.class,
            validateWith = DidMethodParameterValidator.class,
            defaultValueDescription = DidMethodEnum.WEBVH_1_0_STRING)
    //,required = true)
    public DidMethodEnum methodVersion;

    @Override
    protected void execute(CommandContext context) throws VerificationMethodException, DidLogCreatorStrategyException, IOException, VcDataIntegrityCryptographicSuiteException, CommandException, UpdateKeysDidMethodParameterException, NextKeyHashesDidMethodParameterException {
        var didMethod = methodVersion; // may return null
        if (didMethod == null) {
            didMethod = DEFAULT_METHOD_VERSION; // fallback
        }

        var outputDir = context.keyPairStore().getOutputDir().toPath();
        var assertionMethods = getAssertionMethods(outputDir);
        var authentications = getAuthentications(outputDir);

        VcDataIntegrityCryptographicSuite cryptoSuite;
        var keyMaterialLoader = keyMaterialLoader();
        if (keyMaterialLoader.isPresent()) {
            cryptoSuite = keyMaterialLoader.get().loadCryptographicSuite();
        } else {
            var generatedSuite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite();
            cryptoSuite = generatedSuite;

            // avoid generating files, only to overwrite them right after
            if (!shouldGenerateNextVerifyingKeyPem) {
                context.keyPairStore().storeKeysOnDisk(generatedSuite, forceOverwrite);
            }
        }

        if (shouldGenerateNextVerifyingKeyPem) {
            context.keyPairStore().generateAndSaveNewKey(forceOverwrite, nextVerifyingKeyPemFiles);
        }

        var nextKeyPemFiles = nextVerifyingKeyPemFiles;

        // CAUTION At this point, the methodVersion var of type DidMethodEnum MUST be non-null already
        context.println(DidLogCreatorContext.builder(didMethod, cryptoSuite)
                .assertionMethods(assertionMethods)
                .authentications(authentications)
                // Instead of calling deprecated .updateKeys(verifyingKeyPemFiles)
                .updateKeysDidMethodParameter(UpdateKeysDidMethodParameter.of(verifyingKeyPemFiles))
                // Instead of calling deprecated .nextKeys(nextKeyPemFiles)
                .nextKeyHashesDidMethodParameter(NextKeyHashesDidMethodParameter.of(nextKeyPemFiles))
                .build()
                .create(identifierRegistryUrl));
    }
}
