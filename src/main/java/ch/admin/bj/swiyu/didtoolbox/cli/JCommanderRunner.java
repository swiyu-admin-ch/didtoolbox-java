package ch.admin.bj.swiyu.didtoolbox.cli;

import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.CommandBase;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.CommandContext;
import ch.admin.bj.swiyu.didtoolbox.cli.keymaterial.GeneratedKeyPairStore;
import com.beust.jcommander.JCommander;

/**
 * Thin dispatcher running the parsed CLI command.
 * <p>
 * The class is introduced for the sake of being able to test the CLI with no hassle involved.
 */
public final class JCommanderRunner {
    private static final String DEFAULT_BASE_PATH = "./.didtoolbox";

    private final JCommander jc;
    private final String parsedCommandName;
    private final GeneratedKeyPairStore keyPairStore;

    /**
     * Creates a JCommandRunner intended to run the provided command.
     *
     * @param jc
     * @param parsedCommandName
     * @param basePath path to the directory to save generated keys in
     */
    public JCommanderRunner(JCommander jc, String parsedCommandName, String basePath) {
        this.jc = jc;
        this.parsedCommandName = parsedCommandName;
        this.keyPairStore = new GeneratedKeyPairStore(basePath); // may throw IllegalArgumentException
    }

    /**
     * Creates a JCommandRunner intended to run the provided command.
     * Stores generated key material in the `./.didtoolbox` directory
     *
     * @param jc
     * @param parsedCommandName
     */
    public JCommanderRunner(JCommander jc, String parsedCommandName) {
        this(jc, parsedCommandName, DEFAULT_BASE_PATH);
    }

    /**
     * Runs the command (registered with the {@link JCommander} object) denoted by the parsed command name.
     *
     * @throws Exception if the command fails for whatever reason
     */
    public void run() throws Exception { // NOPMD SignatureDeclareThrowsException: each command declares its own (checked) exceptions
        var jcCommand = jc.getCommands().get(parsedCommandName);
        if (jcCommand == null || jcCommand.getObjects().isEmpty()
                || !(jcCommand.getObjects().getFirst() instanceof CommandBase command)) {
            throw new CommandException("Invalid command: " + parsedCommandName);
        }

        command.run(new CommandContext(jc, parsedCommandName, keyPairStore));
    }
}
