package ch.admin.bj.swiyu.didtoolbox.jcommander;

import ch.admin.bj.swiyu.didtoolbox.jcommander.validator.JksFileParameterValidator;
import ch.admin.bj.swiyu.didtoolbox.jcommander.validator.PemFileParameterValidator;
import ch.admin.bj.swiyu.didtoolbox.jcommander.validator.PrimusCredentialsFileParameterValidator;
import ch.admin.bj.swiyu.didtoolbox.securosys.primus.PrimusKeyStoreLoader;
import com.beust.jcommander.Parameter;

import java.io.File;

/**
 * The base class for all Command classes in the package.
 */
abstract class AbstractCommandBase {

    abstract String getCommandName();

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_USAGE, CommandParameterNames.PARAM_NAME_SHORT_USAGE},
            description = "Display help for the DID toolbox command",
            help = true)
    public boolean help;
}
