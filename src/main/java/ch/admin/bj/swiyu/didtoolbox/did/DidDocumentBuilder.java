package ch.admin.bj.swiyu.didtoolbox.did;

import ch.admin.bj.swiyu.didtoolbox.did.model.ProfileVersion;
import ch.admin.bj.swiyu.didtoolbox.did.model.VerificationMethod;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import lombok.Setter;

import java.util.Set;

/**
 * {@link DidDocumentBuilder} is  in charge of
 * <a href="https://www.w3.org/TR/did-1.0/#dfn-did-documents">DID document</a> generation.
 * <p>
 * Once initialized it is recommended to add <a href="https://www.w3.org/TR/did-1.0/#authentication">authentication</a>
 * and <a href="https://www.w3.org/TR/did-1.0/#assertion">assertion</a> methods with
 * {@link DidDocumentBuilder#setAuthentications(Set)} and
 * {@link DidDocumentBuilder#setAssertionMethods(Set)}.
 *
 * This builder object is intended to be used by the builders for Webvh found in
 * {@link ch.admin.bj.swiyu.didtoolbox.did.webvh}.
 */
public class DidDocumentBuilder {

    // Common DID Document attributes
    public static final String DID_DOC_PROPERTY_ID = "id";
    public static final String DID_DOC_PROPERTY_PROFILE_VERSION = "profile_version";
    public static final String DID_DOC_PROPERTY_VERIFICATION_METHOD = "verificationMethod";
    public static final String DID_DOC_PROPERTY_AUTHENTICATION = "authentication";
    public static final String DID_DOC_PROPERTY_ASSERTION_METHOD = "assertionMethod";

    /**
     * Specifies the version of the Swiss Profile the document is.
     * Defaults to {@link ProfileVersion#SWISS_PROFILE_ANCHOR_1_0_0}
     */
    @Setter
    private ProfileVersion profileVersion = ProfileVersion.SWISS_PROFILE_ANCHOR_1_0_0;

    /**
     * Adds <a href="https://www.w3.org/TR/did-1.0/#verification-material">verification material</a> to the resulting
     * DID document as an <a href="https://www.w3.org/TR/did-1.0/#assertion">assertion</a> relation.
     */
    public DidDocumentBuilder setAssertionMethods(Set<VerificationMethod> assertionMethods) {
        this.assertionMethods = assertionMethods;
        return this;
    }
    private Set<VerificationMethod> assertionMethods = Set.of();

    /**
     * Adds <a href="https://www.w3.org/TR/did-1.0/#verification-material">verification material</a> to the resulting
     * DID document as an <a href="https://www.w3.org/TR/did-1.0/#authentication">authentication</a> relation.
     */
    public DidDocumentBuilder setAuthentications(Set<VerificationMethod> authentications) {
        this.authentications = authentications;
        return this;
    }
    private Set<VerificationMethod> authentications = Set.of();

    /**
     * Initializes a new {@link DidDocumentBuilder} with no verification methods.
     * To supply methods, use the {@link DidDocumentBuilder#setAuthentications(Set)} and
     * {@link DidDocumentBuilder#setAssertionMethods(Set)} setters.
     */
    public DidDocumentBuilder() { }

    /**
     * Builds a <a href="https://www.w3.org/TR/did-1.0/#dfn-did-documents">DID document</a>
     * with the provided did as id.
     * See <a href="https://www.w3.org/TR/did-1.0/#example-did-document-with-1-verification-method-type">example</a>.
     *
     * @param did the id of the document and prefix for verification methods kids
     * @return a DID document
     */
    public JsonObject build(String did) {
        var didDoc = new JsonObject();
        didDoc.addProperty(DID_DOC_PROPERTY_ID, did);
        // CAUTION The "controller" property must not be present w.r.t.:
        // - https://jira.bit.admin.ch/browse/EIDSYS-352
        // - https://confluence.bit.admin.ch/x/3e0EMw (DID Doc Conformity Check)

        didDoc.addProperty(DID_DOC_PROPERTY_PROFILE_VERSION, this.profileVersion.toString());

        var verificationMethod = new JsonArray();
        if (authentications != null && !authentications.isEmpty()) {
            didDoc.add(DID_DOC_PROPERTY_AUTHENTICATION, addVerificationMethods(authentications, verificationMethod, did));
        }

        if (assertionMethods != null && !assertionMethods.isEmpty()) {
            didDoc.add(DID_DOC_PROPERTY_ASSERTION_METHOD, addVerificationMethods(assertionMethods, verificationMethod, did));
        }

        if (!verificationMethod.isEmpty()) {
            didDoc.add(DID_DOC_PROPERTY_VERIFICATION_METHOD, verificationMethod);
        }

        return didDoc;
    }

    /**
     * Adds the supplied methods as verification methods to the verificationMethods list and returns a string array
     * of references to the inserted methods.
     *
     * @param methods to be added to the list.
     * @param verificationMethods list of all verification methods.
     * @param did the id of the document.
     * @return String array referencing the methods inserted into verificationMethods.
     */
    private JsonArray addVerificationMethods(Set<VerificationMethod> methods, JsonArray verificationMethods, String did) {
        var method_list = new JsonArray();
        for (var vm : methods) {
            method_list.add(did + "#" + vm.getIdFragment());
            verificationMethods.add(vm.toVerificationMethodEntry(did));
        }
        return method_list;
    }
}
