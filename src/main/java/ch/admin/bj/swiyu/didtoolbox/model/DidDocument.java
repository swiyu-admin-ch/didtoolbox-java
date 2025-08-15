package ch.admin.bj.swiyu.didtoolbox.model;

import com.google.gson.annotations.SerializedName;

import java.util.Set;

/**
 * A helper storing the <a href="https://www.w3.org/TR/did-1.0/#core-properties">DID Document core-properties</a>.
 * <p>
 * However, not all standard props are relevant here, as this class is focusing on quite a few of them such as:
 * <ul>
 *     <li>id</li>
 * </ul>
 */
class DidDocument {
    @SerializedName("@context")
    Set<String> context;
    String id;
    /* TODO Implement as soon is needed
    Set<String> authentication;
    Set<String> assertionMethod;
     */
}