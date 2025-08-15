package ch.admin.bj.swiyu.didtoolbox.model;

import lombok.Getter;

/**
 * This DTO is nothing but a storage for some useful information about a DID log,
 * as specified by any of:
 * <ul>
 * <li><a href="https://identity.foundation/didwebvh/v0.3/">did:tdw DID Method</a> or</li>
 * <li><a href="https://identity.foundation/didwebvh/v1.0/">did:webvh DID Method</a></li>
 * </ul>
 * <p>
 * CAUTION Beware that not all information are relevant here, as this class is focusing on quite a few of them such as:
 * <ul>
 *     <li>{@code versionId} (of the last DID log entry)</li>
 *     <li>{@code versionTime}</li>
 *     <li>DID parameters</li>
 *     <li>DID Doc {@code id}</li>
 * </ul>
 */
public class DidLogMeta {

    @Getter
    final private String lastVersionId;
    @Getter
    int lastVersionNumber;
    @Getter
    final private String dateTime;
    @Getter
    final private DidMethodParameters params;
    @Getter
    final private String didDocId;

    DidLogMeta(String lastVersionId, int lastVersionNumber, String dateTime, DidMethodParameters params, String didDocId) {
        this.lastVersionId = lastVersionId;
        this.lastVersionNumber = lastVersionNumber;
        this.dateTime = dateTime;
        this.params = params;
        this.didDocId = didDocId;
    }
}
