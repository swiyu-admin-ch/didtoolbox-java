package ch.admin.bj.swiyu.didtoolbox.strategy;

import java.net.URL;
import java.time.ZonedDateTime;

/**
 * The interface describing any class capable of creating DID logs, regardless of DID method specification.
 */
public interface DidLogCreatorStrategy {

    /**
     * Creates a valid DID log for a supplied {@code identifierRegistryUrl} and current datetime.
     *
     * @param identifierRegistryUrl is the URL of a did.jsonl in its entirety
     * @return a valid DID log
     * @throws DidLogCreatorStrategyException if creation fails for whatever reason
     */
    String createDidLog(URL identifierRegistryUrl) throws DidLogCreatorStrategyException;

    /**
     * Creates a DID log for supplied {@code identifierRegistryUrl} and {@code datetime}.
     *
     * @param identifierRegistryUrl (of a did.jsonl) in its entirety
     * @param datetime              a date-time with a time-zone in the ISO-8601 calendar system
     * @return a valid DID log
     * @throws DidLogCreatorStrategyException if creation fails for whatever reason
     */
    String createDidLog(URL identifierRegistryUrl, ZonedDateTime datetime) throws DidLogCreatorStrategyException;
}