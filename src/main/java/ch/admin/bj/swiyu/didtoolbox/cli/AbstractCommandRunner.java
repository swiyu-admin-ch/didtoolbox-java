package ch.admin.bj.swiyu.didtoolbox.cli;

import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.CommandBase;
import ch.admin.bj.swiyu.didtoolbox.did.DidLogMeta;
import ch.admin.bj.swiyu.didtoolbox.did.DidLogMetaPeekerException;
import ch.admin.bj.swiyu.didtoolbox.did.tdw.TdwDidLogMetaPeeker;
import ch.admin.bj.swiyu.didtoolbox.did.webvh.WebVerifiableHistoryDidLogMetaPeeker;
import com.beust.jcommander.JCommander;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

/**
 * The base class for all runners, each of them executing a single CLI command.
 * <p>
 * Takes care of the command-agnostic part i.e. printing the command usage if requested.
 *
 * @param <C> type of the command to run
 */
abstract class AbstractCommandRunner<C extends CommandBase> {

    private final JCommander jc;
    private final String commandName;

    AbstractCommandRunner(JCommander jc, String commandName) {
        this.jc = jc;
        this.commandName = commandName;
    }

    /**
     * Runs the supplied command, or prints its usage if requested.
     *
     * @param command containing the parsed CLI parameters
     */
    final void run(C command) throws Exception { // NOPMD SignatureDeclareThrowsException: each runner declares its own (checked) exceptions
        if (command.help) {
            jc.usage(commandName);
            return;
        }
        execute(command);
    }

    /**
     * Executes the actual command logic.
     *
     * @param command containing the parsed CLI parameters
     */
    abstract void execute(C command) throws Exception; // NOPMD SignatureDeclareThrowsException: each runner declares its own (checked) exceptions

    void println(CharSequence output) {
        jc.getConsole().println(output);
    }

    /**
     * Simple helper for extracting DID method parameters in a specification-agnostic fashion.
     *
     * @param didLogFile {@code File} object containing a valid DID log
     * @return a {@code DidLogMeta} object, never {@code null}
     */
    static DidLogMeta fetchDidLogMeta(File didLogFile) throws CommandException {
        String didLog;
        try {
            didLog = Files.readString(didLogFile.toPath());
        } catch (IOException exc) {
            throw new CommandException("Failed to read the supplied DID log file: " + didLogFile.getName(), exc);
        }

        DidLogMeta didLogMeta;
        try {
            didLogMeta = TdwDidLogMetaPeeker.peek(didLog); // assume a did:tdw log
        } catch (DidLogMetaPeekerException exc) { // not a did:tdw log
            try {
                didLogMeta = WebVerifiableHistoryDidLogMetaPeeker.peek(didLog); // assume a did:webvh log
            } catch (DidLogMetaPeekerException exc1) { // not a did:webvh log
                throw new CommandException("The supplied file contains unsupported DID log format: " + didLogFile.getName(), exc1); // NOPMD PreserveStackTrace: false positive
            }
        }

        if (didLogMeta.getParams() == null ||
                didLogMeta.getParams().getDidMethodEnum() == null) {
            throw new CommandException("The supplied DID log features incomplete metadata: " + didLogFile.getName());
        }

        return didLogMeta;
    }
}
