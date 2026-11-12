package ch.admin.bj.swiyu.didtoolbox.did.model;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.Objects;

public class JsonWebKeyVerificationMethod implements VerificationMethod {
    private final String METHOD_TYPE = "JsonWebKey2020";

    private final String kid;
    private final JsonObject jsonObject;

    public JsonWebKeyVerificationMethod(String kid, JsonObject jsonObject) {
        this.kid = kid;
        this.jsonObject = jsonObject.deepCopy();
        this.jsonObject.addProperty("kid", kid);
    }


    @Override
    public String getIdFragment() {
        return kid;
    }

    @Override
    public String getType() {
        return METHOD_TYPE;
    }

    @Override
    public String getPublicKey() {
        return jsonObject.toString();
    }

    @Override
    public boolean equals(Object obj) {
        return this.defaultEquals(obj);
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.getIdFragment());
    }

    /**
     * @param did the did to be used as part of the id together with the idFragment
     * @return the verification method with publicKeyJwk
     */
    @Override
    public JsonObject toVerificationMethodEntry(String did) {
        JsonObject verificationMethodObj = VerificationMethod.super.toVerificationMethodEntry(did);
        verificationMethodObj.add("publicKeyJwk", JsonParser.parseString(getPublicKey()).getAsJsonObject());
        return verificationMethodObj;
    }
}
