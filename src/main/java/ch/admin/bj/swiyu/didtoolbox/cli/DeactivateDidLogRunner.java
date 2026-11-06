package ch.admin.bj.swiyu.didtoolbox.cli;

import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.DeactivateDidLogCommand;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogDeactivatorContext;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogDeactivatorStrategyException;
import com.beust.jcommander.JCommander;

import java.io.IOException;
import java.nio.file.Files;

/**
 * Runs the {@link DeactivateDidLogCommand}.
 */
final class DeactivateDidLogRunner extends AbstractCommandRunner<DeactivateDidLogCommand> {

    DeactivateDidLogRunner(JCommander jc, String commandName) {
        super(jc, commandName);
    }

    @Override
    void execute(DeactivateDidLogCommand command) throws CommandException, VcDataIntegrityCryptographicSuiteException, IOException, DidLogDeactivatorStrategyException {
        var didLogFile = command.didLogFile;
        var didLogMeta = fetchDidLogMeta(didLogFile);

        var cryptoSuite = KeyMaterialLoaderFactory.from(command)
                .orElseThrow(() -> new CommandException("No valid source of signing/verifying ed25519 keys supplied. Use one of the relevant options to supply keys"))
                .loadCryptographicSuite();

        // CAUTION Trimming the existing DID log prevents ending up having multiple line separators in between (after appending the new entry)
        println(Files.readString(didLogFile.toPath()).trim() + System.lineSeparator() +
                DidLogDeactivatorContext.builder(didLogMeta.getParams().getDidMethodEnum(), cryptoSuite)
                        .build()
                        .deactivate(didLogFile));
    }
}
