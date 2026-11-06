package ch.admin.bj.swiyu.didtoolbox.cli;

import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.CreateDidLogCommand;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogCreatorContext;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogCreatorStrategyException;
import ch.admin.bj.swiyu.didtoolbox.did.model.NextKeyHashesDidMethodParameter;
import ch.admin.bj.swiyu.didtoolbox.did.model.NextKeyHashesDidMethodParameterException;
import ch.admin.bj.swiyu.didtoolbox.did.model.UpdateKeysDidMethodParameter;
import ch.admin.bj.swiyu.didtoolbox.did.model.UpdateKeysDidMethodParameterException;
import ch.admin.bj.swiyu.didtoolbox.did.model.VerificationMethodException;
import com.beust.jcommander.JCommander;

import java.io.IOException;

/**
 * Runs the {@link CreateDidLogCommand}.
 */
final class CreateDidLogRunner extends AbstractCommandRunner<CreateDidLogCommand> {

    private final GeneratedKeyPairStore keyPairStore;

    CreateDidLogRunner(JCommander jc, String commandName, GeneratedKeyPairStore keyPairStore) {
        super(jc, commandName);
        this.keyPairStore = keyPairStore;
    }

    @Override
    void execute(CreateDidLogCommand command) throws VerificationMethodException, DidLogCreatorStrategyException, IOException, VcDataIntegrityCryptographicSuiteException, CommandException, UpdateKeysDidMethodParameterException, NextKeyHashesDidMethodParameterException {
        var identifierRegistryUrl = command.identifierRegistryUrl;

        var didMethod = command.methodVersion; // may return null
        if (didMethod == null) {
            didMethod = CreateDidLogCommand.DEFAULT_METHOD_VERSION; // fallback
        }

        var outputDir = keyPairStore.getOutputDir().toPath();
        var assertionMethods = command.getAssertionMethods(outputDir);
        var authentications = command.getAuthentications(outputDir);

        VcDataIntegrityCryptographicSuite cryptoSuite;
        var keyMaterialLoader = KeyMaterialLoaderFactory.from(command);
        if (keyMaterialLoader.isPresent()) {
            cryptoSuite = keyMaterialLoader.get().loadCryptographicSuite();
        } else {
            var generatedSuite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite();
            cryptoSuite = generatedSuite;

            // avoid generating files, only to overwrite them right after
            if (!command.shouldGenerateNextVerifyingKeyPem) {
                keyPairStore.storeKeysOnDisk(generatedSuite, command.forceOverwrite);
            }
        }

        if (command.shouldGenerateNextVerifyingKeyPem) {
            keyPairStore.generateAndSaveNewKey(command.forceOverwrite, command.nextVerifyingKeyPemFiles);
        }

        var verifyingKeyPemFiles = command.verifyingKeyPemFiles;
        var nextKeyPemFiles = command.nextVerifyingKeyPemFiles;

        // CAUTION At this point, the methodVersion var of type DidMethodEnum MUST be non-null already
        println(DidLogCreatorContext.builder(didMethod, cryptoSuite)
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
