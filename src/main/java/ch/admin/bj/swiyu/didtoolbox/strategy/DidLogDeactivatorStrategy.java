package ch.admin.bj.swiyu.didtoolbox.strategy;

import java.io.File;
import java.time.ZonedDateTime;

/**
 * The interface describing any class capable of deactivating existing DID logs, regardless of DID method specification.
 */
public interface DidLogDeactivatorStrategy {

    /**
     * Immediately deactivates a presumably valid DID log.
     *
     * @param didLog to deactivate. Expected to be resolvable/verifiable already.
     * @return a whole new DID log entry to be appended to the supplied {@code didLog}
     * @throws DidLogDeactivatorStrategyException if deactivation fails for whatever reason.
     */
    String deactivateDidLog(String didLog) throws DidLogDeactivatorStrategyException;

    /**
     * The file-system-as-input variation of {@link #deactivateDidLog(String)}
     *
     * @param didLogFile a file featuring a presumably valid DID log to deactivate
     * @return a whole new DID log entry to be appended to the supplied {@code didLog}
     * @throws DidLogDeactivatorStrategyException if deactivation fails for whatever reason
     */
    String deactivateDidLog(File didLogFile) throws DidLogDeactivatorStrategyException;

    /**
     * Deactivates a supplied DID log for the specific datetime.
     *
     * @param didLog   to deactivate. Expected to be resolvable/verifiable already.
     * @param datetime a date-time with a time-zone in the ISO-8601 calendar system
     * @return a whole new  DID log entry to be appended to the supplied {@code didLog}
     * @throws DidLogDeactivatorStrategyException if deactivation fails for whatever reason.
     */
    String deactivateDidLog(String didLog, ZonedDateTime datetime) throws DidLogDeactivatorStrategyException;
}