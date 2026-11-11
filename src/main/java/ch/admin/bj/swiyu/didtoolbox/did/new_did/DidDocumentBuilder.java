package ch.admin.bj.swiyu.didtoolbox.did.new_did;

import ch.admin.bj.swiyu.didtoolbox.did.model.DidMethodEnum;
import ch.admin.bj.swiyu.didtoolbox.did.model.ProfileVersion;
import ch.admin.bj.swiyu.didtoolbox.did.model.VerificationMethod;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import lombok.Setter;

import java.net.URL;
import java.util.Set;

public class DidDocumentBuilder {

    // TODO@MP maybe change to buidler pattern

    // Common DID Document attributes
    public static final String DID_DOC_PROPERTY_ID = "id";
    public static final String DID_DOC_PROPERTY_PROFILE_VERSION = "profile_version";
    public static final String DID_DOC_PROPERTY_VERIFICATION_METHOD = "verificationMethod";
    public static final String DID_DOC_PROPERTY_AUTHENTICATION = "authentication";
    public static final String DID_DOC_PROPERTY_ASSERTION_METHOD = "assertionMethod";

    @Setter
    private ProfileVersion profileVersion = ProfileVersion.SWISS_PROFILE_ANCHOR_1_0_0;

    /**
     * Introduced for the purpose of supplying <a href="https://www.w3.org/TR/did-1.0/#verification-material">verification material</a>
     * for a DID document.
     * More specifically, the focus here is on <a href="https://www.w3.org/TR/did-1.0/#assertion">assertion</a>
     * verification relationships.
     *
     * @since 1.9.0
     */
    @Setter
    private Set<VerificationMethod> assertionMethods = Set.of();

    /**
     * Introduced for the purpose of supplying <a href="https://www.w3.org/TR/did-1.0/#verification-material">verification material</a>
     * for DID document.
     * More specifically, the focus here is on <a href="https://www.w3.org/TR/did-1.0/#authentication">authentication</a>
     * verification relationships.
     *
     * @since 1.9.0
     */
    @Setter
    private Set<VerificationMethod> authentications = Set.of();

    public DidDocumentBuilder() {
    }


    /**
     * Builds a <a href="https://identity.foundation/didwebvh/v1.0/#method-specific-identifier">method-specific identifier</a>
     * w.r.t. <a href="https://identity.foundation/didwebvh/v1.0/#the-did-to-https-transformation">DID-to-HTTPS-transformation</a>.
     * <p>
     * See <a href="https://identity.foundation/didwebvh/v1.0/#example-3">example</a>.
     *
     * @param identifierRegistryUrl an HTTPS URL to transform from
     * @return a DID method-specific identifier
     */
    public JsonObject build(DidMethodEnum method, URL identifierRegistryUrl) {
        var did = "%s:{SCID}:%s".formatted(method.getPrefix(), identifierRegistryUrl.getHost());
        int port = identifierRegistryUrl.getPort(); // the port number, or -1 if the port is not set
        if (port != -1) {
            did = "%s%%3A%d".formatted(did, port);
        }
        String path = identifierRegistryUrl.getPath(); // the path part of this URL, or an empty string if one does not exist
        if (!path.isEmpty()) {
            did = "%s%s".formatted(did,
                    path.replace("/did.jsonl", "") // cleanup
                            .replace("/", ":")); // w.r.t. https://identity.foundation/didwebvh/v1.0/#the-did-to-https-transformation
        }
        return this.build(did);
    }

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

        didDoc.add(DID_DOC_PROPERTY_VERIFICATION_METHOD, verificationMethod);

        return didDoc;
    }

    private JsonArray addVerificationMethods(Set<VerificationMethod> methods, JsonArray verificationMethods, String did) {
        var method_list = new JsonArray();
        for (var vm : methods) {
            method_list.add(did + "#" + vm.getIdFragment());
            verificationMethods.add(buildVerificationMethodWithPublicKeyJwk(did, vm.getIdFragment(), vm.getVerificationMaterial().getPublicKeyJwk()));
        }
        return method_list;
    }

    private static JsonObject buildVerificationMethodWithPublicKeyJwk(String did, String fragmentId, String publicKeyJwk) {
        var verificationMethodObj = new JsonObject();
        verificationMethodObj.addProperty("id", did + "#" + fragmentId);
        // According to swiss profile anchor 1.0 (https://confluence.bit.admin.ch/x/VL8VTQ)
        // controller must be the did itself
        verificationMethodObj.addProperty("controller", did);
        // CAUTION The "controller" property must not be present w.r.t.:
        // - https://confluence.bit.admin.ch/x/3e0EMw (DID Doc Conformity Check)
        verificationMethodObj.addProperty("type", "JsonWebKey2020");
        // CAUTION The "publicKeyMultibase" property must not be present w.r.t.:
        // - https://confluence.bit.admin.ch/x/3e0EMw (DID Doc Conformity Check)
        verificationMethodObj.add("publicKeyJwk", JsonParser.parseString(publicKeyJwk).getAsJsonObject());

        return verificationMethodObj;
    }
}
