package ch.admin.bj.swiyu.didtoolbox.context;

import java.io.File;
import java.time.ZonedDateTime;

/**
 * The interface describing any class capable of updating existing DID logs, regardless of DID method specification.
 */
public interface DidLogUpdaterStrategy {

    /**
     * Updates an existing (and presumably valid) DID log.
     *
     * @param resolvableDidLog to update. Expected to be resolvable/verifiable already.
     * @return a whole new DID log entry to be appended to the existing {@code resolvableDidLog}
     * @throws DidLogUpdaterStrategyException if update fails for whatever reason.
     */
    String updateDidLog(String resolvableDidLog) throws DidLogUpdaterStrategyException;

    /**
     * The file-system-as-input variation of {@link #updateDidLog(String)}
     *
     * @param resolvableDidLogFile a file featuring DID log to update
     * @return a whole new DID log entry to be appended to the existing {@code resolvableDidLogFile}
     * @throws DidLogUpdaterStrategyException if update fails for whatever reason
     */
    String updateDidLog(File resolvableDidLogFile) throws DidLogUpdaterStrategyException;

    /**
     * Updates a valid DID log for a supplied datetime.
     *
     * @param resolvableDidLog to update. Expected to be resolvable/verifiable already.
     * @param zdt              a date-time with a time-zone in the ISO-8601 calendar system
     * @return a whole new DID log entry to be appended to the existing {@code resolvableDidLog}
     * @throws DidLogUpdaterStrategyException if update fails for whatever reason.
     */
    String updateDidLog(String resolvableDidLog, ZonedDateTime zdt) throws DidLogUpdaterStrategyException;
}