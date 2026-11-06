package ch.admin.bj.swiyu.didtoolbox.cli;

import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.UpdateDidLogCommand;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogUpdaterContext;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogUpdaterStrategyException;
import ch.admin.bj.swiyu.didtoolbox.did.model.NextKeyHashesDidMethodParameter;
import ch.admin.bj.swiyu.didtoolbox.did.model.NextKeyHashesDidMethodParameterException;
import ch.admin.bj.swiyu.didtoolbox.did.model.UpdateKeysDidMethodParameter;
import ch.admin.bj.swiyu.didtoolbox.did.model.UpdateKeysDidMethodParameterException;
import ch.admin.bj.swiyu.didtoolbox.did.model.VerificationMethodException;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;

import java.io.IOException;
import java.nio.file.Files;

import static ch.admin.bj.swiyu.didtoolbox.cli.jcommander.CommandParameterNames.PARAM_NAME_LONG_GENERATE_NEW_VERIFYING_KEY;
import static ch.admin.bj.swiyu.didtoolbox.cli.jcommander.CommandParameterNames.PARAM_NAME_LONG_GENERATE_NEXT_VERIFYING_KEY;

/**
 * Runs the {@link UpdateDidLogCommand}.
 */
final class UpdateDidLogRunner extends AbstractCommandRunner<UpdateDidLogCommand> {

    private final GeneratedKeyPairStore keyPairStore;

    UpdateDidLogRunner(JCommander jc, String commandName, GeneratedKeyPairStore keyPairStore) {
        super(jc, commandName);
        this.keyPairStore = keyPairStore;
    }

    @Override
    void execute(UpdateDidLogCommand command) throws CommandException, VerificationMethodException, IOException, VcDataIntegrityCryptographicSuiteException, UpdateKeysDidMethodParameterException, NextKeyHashesDidMethodParameterException, DidLogUpdaterStrategyException {
        var didLogFile = command.didLogFile;

        var didLogMeta = fetchDidLogMeta(didLogFile);

        // CAUTION At this point, it should be all in place to update to be able to update the supplied DID log

        var outputDir = keyPairStore.getOutputDir().toPath();
        var assertionMethods = command.getAssertionMethods(outputDir);
        var authentications = command.getAuthentications(outputDir);

        if (authentications.isEmpty() && assertionMethods.isEmpty()) {
            throw new CommandException("No update will take place as no verification material is supplied whatsoever");
        }

        if (command.shouldGenerateNextVerifyingKeyPem || command.shouldGenerateVerifyingKeyPem) {
            if (command.shouldGenerateNextVerifyingKeyPem && command.shouldGenerateVerifyingKeyPem) {
                throw new ParameterException("Not allowed to use the both flags ('%s', '%s' together".formatted(PARAM_NAME_LONG_GENERATE_NEW_VERIFYING_KEY, PARAM_NAME_LONG_GENERATE_NEXT_VERIFYING_KEY));
            }

            if (command.shouldGenerateNextVerifyingKeyPem) {
                keyPairStore.generateAndSaveNewKey(command.forceOverwrite, command.nextVerifyingKeyPemFiles);
            } else {
                keyPairStore.generateAndSaveNewKey(command.forceOverwrite, command.verifyingKeyPemFiles);
            }
        }

        var verifyingKeyPemFiles = command.verifyingKeyPemFiles;
        var nextVerifyingKeyPemFiles = command.nextVerifyingKeyPemFiles; // if set, denotes key pre-rotation

        var cryptoSuite = KeyMaterialLoaderFactory.from(command)
                .orElseThrow(() -> new CommandException("Incomplete source of the (signing/verifying) ed25519 keys supplied. Use one of the relevant options to supply keys"))
                .loadCryptographicSuite();

        if (didLogMeta.isKeyPreRotationActivated() && !didLogMeta.isPreRotatedUpdateKey(cryptoSuite.getVerificationKeyMultibase())) {
            throw new CommandException("Illegal signing (private) ed25519 key supplied");
        }

        // CAUTION At this point, the methodVersion var of type DidMethodEnum MUST be non-null already
        println(Files.readString(didLogFile.toPath()).trim() + System.lineSeparator() +
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
