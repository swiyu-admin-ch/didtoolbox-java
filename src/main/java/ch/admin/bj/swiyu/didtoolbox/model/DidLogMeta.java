package ch.admin.bj.swiyu.didtoolbox.model;

import ch.admin.eid.did_sidekicks.DidDoc;
import ch.admin.eid.did_sidekicks.DidMethodParameter;
import lombok.Getter;

import java.util.HashSet;
import java.util.Map;
import java.util.Objects;

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
    private NamedDidMethodParameters params;
    @Getter
    final private DidDoc didDoc;

    DidLogMeta(String lastVersionId, int lastVersionNumber, String dateTime, Map<String, DidMethodParameter> paramsMap, DidDoc didDoc) {
        this.lastVersionId = lastVersionId;
        this.lastVersionNumber = lastVersionNumber;
        this.dateTime = dateTime;
        this.setParams(paramsMap);
        this.didDoc = didDoc;
    }

    private void setParams(Map<String, DidMethodParameter> paramsMap) {
        var metaParams = new NamedDidMethodParameters();
        Objects.requireNonNull(paramsMap).forEach((name, param) -> {
            if (name.equals("method") && param.isString()) {
                metaParams.setMethod(param.getStringValue());
            } else if (name.equals("scid") && param.isString()) {
                metaParams.setScid(param.getStringValue());
            } else if (name.equals("update_keys") && param.isArray() && !param.isEmptyArray()) {
                metaParams.setUpdateKeys(new HashSet<>(Objects.requireNonNull(param.getStringArrayValue())));
            } else if (name.equals("deactivated") && param.isBool()) {
                metaParams.setDeactivated(param.getBoolValue());
            }
        });

        this.params = metaParams;
    }
}
