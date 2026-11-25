package ch.admin.bj.swiyu.didtoolbox.cli.jcommander;

import ch.admin.bj.swiyu.didtoolbox.cli.CommandException;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.converter.IdentifierRegistryUrlParameterConverter;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.validator.CommandParametersValidator;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.validator.IdentifierRegistryUrlParameterValidator;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import ch.admin.bj.swiyu.didtoolbox.did.model.DidMethodEnum;
import ch.admin.bj.swiyu.didtoolbox.did.model.NextKeyHashesDidMethodParameter;
import ch.admin.bj.swiyu.didtoolbox.did.model.NextKeyHashesDidMethodParameterException;
import ch.admin.bj.swiyu.didtoolbox.did.model.UpdateKeysDidMethodParameter;
import ch.admin.bj.swiyu.didtoolbox.did.model.UpdateKeysDidMethodParameterException;
import ch.admin.bj.swiyu.didtoolbox.did.model.VerificationMethodException;
import ch.admin.bj.swiyu.didtoolbox.did.DidDocumentBuilder;
import ch.admin.bj.swiyu.didtoolbox.did.webvh.WebVerifiableHistoryCreator;
import ch.admin.bj.swiyu.didtoolbox.did.webvh.WebVerifiableHistoryException;
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

    public static final DidMethodEnum didMethod = DidMethodEnum.WEBVH_1_0;

    @Parameter(names = {"--identifier-registry-url", "-u"},
            description = "A HTTP(S) DID URL (to did.jsonl) to create a DID log for",
            required = true,
            converter = IdentifierRegistryUrlParameterConverter.class,
            validateWith = IdentifierRegistryUrlParameterValidator.class)
    public URL identifierRegistryUrl;

    @Override
    protected void execute(CommandContext context) throws VerificationMethodException, IOException, VcDataIntegrityCryptographicSuiteException, CommandException, UpdateKeysDidMethodParameterException, NextKeyHashesDidMethodParameterException, WebVerifiableHistoryException {
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

        var didDocumentBuilder = new DidDocumentBuilder()
                .setAssertionMethods(assertionMethods)
                .setAuthentications(authentications);
        var logCreator = WebVerifiableHistoryCreator.builder(didDocumentBuilder, cryptoSuite)
                .didMethod(didMethod)
                .updateKeys(UpdateKeysDidMethodParameter.of(verifyingKeyPemFiles))
                .nextKeyHashes(NextKeyHashesDidMethodParameter.of(nextKeyPemFiles))
                .build();
        context.println(logCreator.createDidLog(identifierRegistryUrl));
    }
}
