package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorStrategyException;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogDeactivatorStrategyException;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogUpdaterStrategyException;
import ch.admin.bj.swiyu.didtoolbox.jcommander.*;
import ch.admin.bj.swiyu.didtoolbox.jcommander.RootCommandParameter;
import ch.admin.bj.swiyu.didtoolbox.model.NextKeyHashesDidMethodParameterException;
import ch.admin.bj.swiyu.didtoolbox.model.UpdateKeysDidMethodParameterException;
import ch.admin.bj.swiyu.didtoolbox.model.VerificationMethodException;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import com.beust.jcommander.UnixStyleUsageFormatter;
import com.beust.jcommander.internal.Console;
import com.beust.jcommander.internal.DefaultConsole;

import java.io.IOException;
import java.security.KeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;

@SuppressWarnings({"PMD.DoNotTerminateVM", "PMD.CyclomaticComplexity"})
public class Main {
    private final Console console;

    /**
     * Entrypoint of the cli, prints output to the stdout.
     * @param args Arguments to CLI is called with
     */
    public static void main(String... args) {
        var main = new Main(new DefaultConsole());
        var exitCode = main.run(args);
        if (exitCode != 0) {
            System.exit(exitCode);
        }
    }

    /**
     * Instantiates the main, allowing for custom console/output
     * @param console Console to print the output to
     */
    public Main(Console console) {
        this.console = console;
    }

    /**
     * Runs the CLI
     * @param args cli arguments to be parsed and then executed
     * @return the exit code
     */
    public int run(String[] args) {
        var rootParameters = new RootCommandParameter();
        var createDidLogCommand = new CreateDidLogCommand();
        var updateDidLogCommand = new UpdateDidLogCommand();
        var deactivateCommand = new DeactivateDidLogCommand();
        var createProofOfPossessionCommand = new CreateProofOfPossessionCommand();
        var verifyProofOfPossessionCommand = new VerifyProofOfPossessionCommand();
        var jc = JCommander.newBuilder()
                .addObject(rootParameters)
                .console(this.console)
                .addCommand(CreateDidLogCommand.COMMAND_NAME, createDidLogCommand)
                .addCommand(UpdateDidLogCommand.COMMAND_NAME, updateDidLogCommand)
                .addCommand(DeactivateDidLogCommand.COMMAND_NAME, deactivateCommand)
                .addCommand(CreateProofOfPossessionCommand.COMMAND_NAME, createProofOfPossessionCommand)
                .addCommand(VerifyProofOfPossessionCommand.COMMAND_NAME, verifyProofOfPossessionCommand)
                .programName(ManifestUtils.getImplementationTitle())
                .columnSize(150)
                .build();

        var usageFormatter = new UnixStyleUsageFormatter(jc);
        jc.setUsageFormatter(usageFormatter);

        try {
            jc.parse(args);
        } catch (ParameterException e) {
            return printCommandError(jc, null, e.getLocalizedMessage());
        }

        if (rootParameters.version) {
            jc.getConsole().println(ManifestUtils.getImplementationTitle() + " " + ManifestUtils.getImplementationVersion());
            return 0;
        }

        if (rootParameters.help) {
            jc.usage();
            return 0;
        }

        var parsedCommandName = jc.getParsedCommand();
        if (parsedCommandName == null) {
            jc.usage();
            return 1;
        }

        var commandRunner = new JCommanderRunner(jc, parsedCommandName);
        try {
            return switch (parsedCommandName) {
                case CreateDidLogCommand.COMMAND_NAME -> commandRunner.runCreateDidLogCommand(createDidLogCommand);
                case UpdateDidLogCommand.COMMAND_NAME -> commandRunner.runUpdateDidLogCommand(updateDidLogCommand);
                case DeactivateDidLogCommand.COMMAND_NAME ->
                        commandRunner.runDeactivateDidLogCommand(deactivateCommand);
                case CreateProofOfPossessionCommand.COMMAND_NAME ->
                        commandRunner.runPoPCreateCommand(createProofOfPossessionCommand);
                case VerifyProofOfPossessionCommand.COMMAND_NAME ->
                        commandRunner.runPoPVerifyCommand(verifyProofOfPossessionCommand);
                default -> printCommandError(jc, null, "Invalid command: " + parsedCommandName);
            };
        } catch (IOException | UnrecoverableEntryException | VcDataIntegrityCryptographicSuiteException |
                 KeyStoreException | NoSuchAlgorithmException | KeyException | DidLogDeactivatorStrategyException |
                 ProofOfPossessionCreatorException | DidLogCreatorStrategyException |
                 NextKeyHashesDidMethodParameterException | UpdateKeysDidMethodParameterException |
                 VerificationMethodException | DidLogUpdaterStrategyException e) {
            return printCommandError(jc, parsedCommandName, "Running command '" + parsedCommandName + "' failed due to: " + e.getLocalizedMessage());
        }
    }

    private int printCommandError(JCommander jc, String commandName, String message) {
        jc.getConsole().println(message);
        jc.getConsole().println("");
        if (commandName != null) {
            jc.getConsole().println("For detailed usage, run: " + ManifestUtils.getImplementationTitle() + " " + commandName + " -h");
        } else {
            jc.getConsole().println("For detailed usage, run: " + ManifestUtils.getImplementationTitle() + " -h");
        }
        return 1;
    }
}