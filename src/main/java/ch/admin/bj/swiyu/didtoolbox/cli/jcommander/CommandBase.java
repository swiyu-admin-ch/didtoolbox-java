package ch.admin.bj.swiyu.didtoolbox.cli.jcommander;

import com.beust.jcommander.Parameter;

/**
 * The base class for all Command classes in the package.
 */
public class CommandBase {

    protected CommandBase() { // not meant to be instantiated directly
    }

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_USAGE, CommandParameterNames.PARAM_NAME_SHORT_USAGE},
            description = "Display help for the DID toolbox command",
            help = true)
    public boolean help;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_VERBOSE},
            description = "On error, print the full cause chain")
    public boolean verbose;
}
