package ch.admin.bj.swiyu.didtoolbox.cli.jcommander;

import ch.admin.bj.swiyu.didtoolbox.cli.keymaterial.GeneratedKeyPairStore;
import com.beust.jcommander.JCommander;

/**
 * The run-time collaborators of a command.
 * <p>
 * The command objects are instantiated before the command line gets parsed, so these cannot be supplied
 * at construction time and are handed over when running the command instead.
 *
 * @param jc           the root {@link JCommander} object, being the one with the console configured
 * @param commandName  the name of the command to run
 * @param keyPairStore for persisting the generated key pairs
 */
public record CommandContext(JCommander jc, String commandName, GeneratedKeyPairStore keyPairStore) {

    void printUsage() {
        jc.usage(commandName);
    }

    void println(CharSequence output) {
        jc.getConsole().println(output);
    }
}
