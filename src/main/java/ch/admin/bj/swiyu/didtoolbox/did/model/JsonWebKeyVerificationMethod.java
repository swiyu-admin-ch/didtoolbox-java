package ch.admin.bj.swiyu.didtoolbox.did.model;

import com.google.gson.JsonObject;

import java.util.Objects;

public class JsonWebKeyVerificationMethod implements VerificationMethod {
    String VM_TYPE_JSON_WEB_KEY_2020 = "JsonWebKey2020";

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
        return VM_TYPE_JSON_WEB_KEY_2020;
    }

    @Override
    public String getPublicKeyJwk() {
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
}
