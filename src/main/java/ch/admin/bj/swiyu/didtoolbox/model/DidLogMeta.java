package ch.admin.bj.swiyu.didtoolbox.model;

import ch.admin.bj.swiyu.didtoolbox.JCSHasher;
import ch.admin.bj.swiyu.didtoolbox.PemUtils;
import ch.admin.eid.did_sidekicks.DidDoc;
import ch.admin.eid.did_sidekicks.DidMethodParameter;
import lombok.Getter;

import java.io.File;
import java.io.IOException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

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
    final int lastVersionNumber;
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
            } else if (name.equals(NamedDidMethodParameters.UPDATE_KEYS) && param.isArray() && !param.isEmptyArray()) {
                metaParams.setUpdateKeys(new HashSet<>(Objects.requireNonNull(param.getStringArrayValue())));
            } else if (name.equals(NamedDidMethodParameters.NEXT_KEY_HASHES) && param.isArray() && !param.isEmptyArray()) {
                metaParams.setNextKeyHashes(new HashSet<>(Objects.requireNonNull(param.getStringArrayValue())));
            } else if (name.equals("deactivated") && param.isBool()) {
                metaParams.setDeactivated(param.getBoolValue());
            }
        });

        this.params = metaParams;
    }

    /**
     * W.r.t. {@code nextKeyHashes} DID method parameter value.
     *
     * @return {@code true} if and only if the {@code nextKeyHashes} DID method parameter is set and non-empty. Otherwise, {@code false}.
     */
    public boolean isKeyPreRotationActivated() {
        var nextKeyHashesParam = this.getParams().getNextKeyHashes();
        return nextKeyHashesParam != null && !nextKeyHashesParam.isEmpty();
    }

    /**
     * In case of activated key pre-rotation, the method proves whether the supplied {@code multikey} is among those
     * defined by the key pre-rotation, or not.
     *
     * @param multikey to check
     * @return {@code true} if and only if the supplied {@code multikey} is legal w.r.t. key pre-rotation. Otherwise, {@code false}.
     */
    public boolean isPreRotatedUpdateKey(String multikey) {

        if (this.isKeyPreRotationActivated() && multikey != null) {
            return this.getParams().getNextKeyHashes().contains(JCSHasher.buildNextKeyHash(multikey));
        }

        return false;
    }

    /**
     * In case of activated key pre-rotation, the method proves whether the supplied {@code pemFiles} feature public keys
     * that are among those defined by the key pre-rotation, or not.
     *
     * @param pemFiles to check
     * @return {@code true} if and only if at least one of the supplied {@code pemFiles} is legal w.r.t. key pre-rotation. Otherwise, {@code false}.
     * @throws IOException             in case at least one of the supplied {@code pemFiles} features no PEM content
     * @throws InvalidKeySpecException in case at least one of the supplied {@code pemFiles} contains no valid Ed25519 public key
     */
    public boolean arePreRotatedUpdateKeys(Set<File> pemFiles) throws InvalidKeySpecException, IOException {

        if (pemFiles != null && !pemFiles.isEmpty()) {
            for (var pemFile : pemFiles) {
                if (!this.isPreRotatedUpdateKey(PemUtils.parsePEMFilePublicKeyEd25519Multibase(pemFile))) {
                    return false;
                }
            }
        }

        return true;
    }
}
