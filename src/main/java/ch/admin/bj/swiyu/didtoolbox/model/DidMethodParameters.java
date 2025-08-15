package ch.admin.bj.swiyu.didtoolbox.model;

import lombok.Getter;

import java.util.Set;

/**
 * This DTO stores either of:
 * <ul>
 * <li><a href="https://identity.foundation/didwebvh/v0.3/#didtdw-did-method-parameters">did:tdw DID Method Parameters</a> or</li>
 * <li><a href="https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters">did:webvh DID Method Parameters</a></li>
 * </ul>
 * <p>
 * CAUTION Beware that not all standard params are relevant here, as this class is focusing on quite a few of them such as:
 * <ul>
 *     <li>{@code method}</li>
 *     <li>{@code scid}</li>
 *     <li>{@code updateKeys}</li>
 *     <li>{@code deactivated}</li>
 * </ul>
 */
public class DidMethodParameters {

    String method;
    String scid;
    @Getter
    Set<String> updateKeys;
    @Getter
    Boolean deactivated;

    void mergeFrom(DidMethodParameters other) {
        if (other.method != null && !other.method.isEmpty()) {
            this.method = other.method;
        }
        if (other.scid != null && !other.scid.isEmpty()) {
            this.scid = other.scid;
        }
        if (other.updateKeys != null && !other.updateKeys.isEmpty()) {
            this.updateKeys = other.updateKeys;
        }
        if (other.deactivated != null) {
            this.deactivated = other.deactivated;
        }
    }
}
