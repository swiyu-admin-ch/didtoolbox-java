package ch.admin.bj.swiyu.didtoolbox.cli.jcommander;

import com.beust.jcommander.Parameter;

/**
 * The base class for all Command classes in the package.
 * <p>
 * Takes care of the command-agnostic part i.e. printing the command usage if requested.
 */
public abstract class CommandBase {

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_USAGE, CommandParameterNames.PARAM_NAME_SHORT_USAGE},
            description = "Display help for the DID toolbox command",
            help = true)
    public boolean help;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_VERBOSE},
            description = "On error, print the full cause chain")
    public boolean verbose;

    /**
     * Runs the command, or prints its usage if requested.
     *
     * @param context the run-time collaborators of the command
     */
    public final void run(CommandContext context) throws Exception { // NOPMD SignatureDeclareThrowsException: each command declares its own (checked) exceptions
        if (help) {
            context.printUsage();
            return;
        }
        execute(context);
    }

    /**
     * Executes the actual command logic.
     *
     * @param context the run-time collaborators of the command
     */
    protected abstract void execute(CommandContext context) throws Exception; // NOPMD SignatureDeclareThrowsException: each command declares its own (checked) exceptions
}
