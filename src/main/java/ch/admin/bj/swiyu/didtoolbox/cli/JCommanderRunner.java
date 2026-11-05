package ch.admin.bj.swiyu.didtoolbox.cli;

import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.*;
import com.beust.jcommander.JCommander;

/**
 * Thin dispatcher delegating the parsed CLI command to its dedicated runner.
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
    public void run() throws Exception { // NOPMD SignatureDeclareThrowsException: each runner declares its own (checked) exceptions
        var jcCommand = jc.getCommands().get(parsedCommandName);
        if (jcCommand == null || jcCommand.getObjects().isEmpty()) {
            throw new CommandException("Invalid command: " + parsedCommandName);
        }

        switch (jcCommand.getObjects().getFirst()) {
            case CreateDidLogCommand command ->
                    new CreateDidLogRunner(jc, parsedCommandName, keyPairStore).run(command);
            case UpdateDidLogCommand command ->
                    new UpdateDidLogRunner(jc, parsedCommandName, keyPairStore).run(command);
            case DeactivateDidLogCommand command -> new DeactivateDidLogRunner(jc, parsedCommandName).run(command);
            case CreateProofOfPossessionCommand command ->
                    new CreateProofOfPossessionRunner(jc, parsedCommandName).run(command);
            case VerifyProofOfPossessionCommand command ->
                    new VerifyProofOfPossessionRunner(jc, parsedCommandName).run(command);
            default -> throw new CommandException("Invalid command: " + parsedCommandName);
        }
    }
}
