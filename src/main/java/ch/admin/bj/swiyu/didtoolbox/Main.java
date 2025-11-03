package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.jcommander.*;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.beust.jcommander.UnixStyleUsageFormatter;

@SuppressWarnings({"PMD.LawOfDemeter", "PMD.CyclomaticComplexity"})
public class Main {

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_USAGE, CommandParameterNames.PARAM_NAME_SHORT_USAGE},
            description = "Display help for the DID toolbox",
            help = true)
    boolean help;

    @Parameter(names = {"--version", "-V"},
            description = "Display version")
    boolean version;

    @SuppressWarnings({"PMD.DoNotTerminateVM"})
    public static void main(String... args) {
        var main = new Main();

        var createDidLogCommand = new CreateDidLogCommand();
        var updateDidLogCommand = new UpdateDidLogCommand();
        var deactivateCommand = new DeactivateDidLogCommand();
        var createProofOfPossessionCommand = new CreateProofOfPossessionCommand();
        var verifyProofOfPossessionCommand = new VerifyProofOfPossessionCommand();
        var jc = JCommander.newBuilder()
                .addObject(main)
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
            overAndOut(jc, null, e.getLocalizedMessage());
        }

        if (main.version) {
            jc.getConsole().println(ManifestUtils.getImplementationTitle() + " " + ManifestUtils.getImplementationVersion());
            System.exit(0);
        }

        if (main.help) {
            jc.usage();
            System.exit(0);
        }

        var parsedCommandName = jc.getParsedCommand();
        if (parsedCommandName == null) {
            jc.usage();
            System.exit(1);
        }

        var commandRunner = new JCommanderRunner(jc, parsedCommandName);
        try {
            switch (parsedCommandName) {
                case CreateDidLogCommand.COMMAND_NAME -> commandRunner.runCreateDidLogCommand(createDidLogCommand);
                case UpdateDidLogCommand.COMMAND_NAME -> commandRunner.runUpdateDidLogCommand(updateDidLogCommand);
                case DeactivateDidLogCommand.COMMAND_NAME ->
                        commandRunner.runDeactivateDidLogCommand(deactivateCommand);
                case CreateProofOfPossessionCommand.COMMAND_NAME ->
                        commandRunner.runPoPCreateCommand(createProofOfPossessionCommand);
                case VerifyProofOfPossessionCommand.COMMAND_NAME ->
                        commandRunner.runPoPVerifyCommand(verifyProofOfPossessionCommand);
                default -> overAndOut(jc, null, "Invalid command: " + parsedCommandName);
            }
        } catch (Throwable e) {
            overAndOut(jc, parsedCommandName, "Running command '" + parsedCommandName + "' failed due to: " + e.getLocalizedMessage());
        }

        System.exit(0);
    }

    @SuppressWarnings({"PMD.DoNotTerminateVM"})
    private static void overAndOut(JCommander jc, String commandName, String message) {
        jc.getConsole().println(message);
        jc.getConsole().println("");
        if (commandName != null) {
            jc.getConsole().println("For detailed usage, run: " + ManifestUtils.getImplementationTitle() + " " + commandName + " -h");
        } else {
            jc.getConsole().println("For detailed usage, run: " + ManifestUtils.getImplementationTitle() + " -h");
        }
        System.exit(1);
    }
}