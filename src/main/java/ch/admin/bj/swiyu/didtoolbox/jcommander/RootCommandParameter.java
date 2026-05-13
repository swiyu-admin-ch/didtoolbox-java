package ch.admin.bj.swiyu.didtoolbox.jcommander;

import com.beust.jcommander.Parameter;

public class RootCommandParameter {
    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_USAGE, CommandParameterNames.PARAM_NAME_SHORT_USAGE},
            description = "Display help for the DID toolbox",
            help = true)
    public boolean help;

    @Parameter(names = {"--version", "-V"},
            description = "Display version")
    public boolean version;
}
