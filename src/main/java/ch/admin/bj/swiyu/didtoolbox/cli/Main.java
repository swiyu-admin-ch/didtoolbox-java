package ch.admin.bj.swiyu.didtoolbox.cli;

import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.*;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.parameter.RootCommandParameter;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import com.beust.jcommander.UnixStyleUsageFormatter;
import com.beust.jcommander.internal.Console;
import com.beust.jcommander.internal.DefaultConsole;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Arrays;

/**
 * Entrypoint of the CLI.
 * <p>
 * Exit codes (see {@link ExitCode}):
 * <ul>
 *   <li>{@code 0} - success</li>
 *   <li>{@code 1} - unexpected error</li>
 *   <li>{@code 2} - usage / parameter validation error</li>
 *   <li>{@code 3} - I/O / environment error (e.g. missing file, HSM unreachable)</li>
 *   <li>{@code 4} - crypto / verification error</li>
 * </ul>
 */
public class Main {
    private final Console console;

    /**
     * Entrypoint of the cli, prints output to the stdout.
     *
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
     *
     * @param console Console to print the output to
     */
    public Main(Console console) {
        this.console = console;
    }

    /**
     * Runs the CLI
     *
     * @param args cli arguments to be parsed and then executed
     * @return the exit code
     */
    public int run(String... args) {
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

        // parsing may stop before a trailing --verbose
        var verbose = Arrays.asList(args).contains(CommandParameterNames.PARAM_NAME_LONG_VERBOSE);

        try {
            jc.parse(args);
        } catch (ParameterException e) {
            return printCommandError(jc, null, "Failed to parse command arguments: " + e.getLocalizedMessage(), e, verbose, ExitCode.of(e));
        }

        if (rootParameters.version) {
            jc.getConsole().println(ManifestUtils.getImplementationTitle() + " " + ManifestUtils.getImplementationVersion());
            return ExitCode.SUCCESS.code();
        }

        if (rootParameters.help) {
            jc.usage();
            return ExitCode.SUCCESS.code();
        }

        var parsedCommandName = jc.getParsedCommand();
        if (parsedCommandName == null) {
            jc.usage();
            return ExitCode.USAGE.code();
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
                default -> {
                    return printCommandError(jc, null, "Invalid command: " + parsedCommandName, null, false, ExitCode.USAGE);
                }
            }
            return ExitCode.SUCCESS.code();
        } catch (Exception e) { // NOPMD AvoidCatchingGenericException: catch generic exception to always print proper error message
            return printCommandError(jc, parsedCommandName, "Failed to run '" + parsedCommandName + "' command due to: " + e.getLocalizedMessage(), e, verbose, ExitCode.of(e));
        }
    }

    private int printCommandError(JCommander jc, String commandName, String message, Throwable cause, boolean verbose, ExitCode exitCode) {
        jc.getConsole().println(message);
        jc.getConsole().println("");
        if (verbose && cause != null) {
            printCauseChain(jc, cause);
            jc.getConsole().println("");
            printStackTrace(jc, cause);
            jc.getConsole().println("");
        }
        if (commandName != null) {
            jc.getConsole().println("For detailed usage, run: " + ManifestUtils.getImplementationTitle() + " " + commandName + " -h");
        } else {
            jc.getConsole().println("For detailed usage, run: " + ManifestUtils.getImplementationTitle() + " -h");
        }
        return exitCode.code();
    }

    private void printCauseChain(JCommander jc, Throwable throwable) {
        jc.getConsole().println("Cause chain:");
        var prefix = "";
        for (var t = throwable; t != null; t = t.getCause()) {
            var message = t.getLocalizedMessage();
            if (message == null || message.isBlank()) {
                jc.getConsole().println(prefix + t.getClass().getName());
            } else {
                jc.getConsole().println(prefix + t.getClass().getName() + ":");
                // message with line indent
                message.lines().forEach(line -> jc.getConsole().println("    " + line));
            }
            prefix = "Caused by: ";
        }
    }

    private void printStackTrace(JCommander jc, Throwable throwable) {
        jc.getConsole().println("Stack trace:");
        var stackTrace = new StringWriter();
        throwable.printStackTrace(new PrintWriter(stackTrace));
        stackTrace.toString().lines().forEach(jc.getConsole()::println);
    }
}