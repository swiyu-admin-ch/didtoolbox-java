package ch.admin.bj.swiyu.didtoolbox.model;

import lombok.Getter;

import java.text.ParseException;

/**
 * The enumeration describing/modelling all the supported specifications
 */
public enum DidMethodEnum {
    /**
     * Refers to <a href="https://identity.foundation/didwebvh/v0.3/">Trust DID Web - did:tdw - v0.3</a>
     */
    TDW_0_3("did:tdw:0.3") {
        @Override
        public boolean isTdw03() {
            return true;
        }
    },
    /**
     * Refers to <a href="https://identity.foundation/didwebvh/v1.0/">The did:webvh DID Method v1.0</a>
     */
    WEBVH_1_0("did:webvh:1.0") {
        @Override
        public boolean isWebVh10() {
            return true;
        }
    };

    public final static String TDW_0_3_STRING = "did:tdw:0.3";

    public final static String WEBVH_1_0_STRING = "did:webvh:1.0";

    private final String didMethod;
    @Getter
    private final String prefix;

    DidMethodEnum(String didMethod) {
        this.didMethod = didMethod;
        var split = didMethod.split(":", 3);
        if (split.length != 3) {
            throw new IllegalArgumentException("A DID method must be supplied in format: 'did:<method-name>:<version>'");
        }
        this.prefix = split[0] + ":" + split[1];
    }

    /**
     * Yet another type conversion helper.
     *
     * @param str to convert to {@link DidMethodEnum} from. Case-insensitive.
     * @return {@code null} if unknown
     * @throws IllegalArgumentException if the supplied string does not match any of the valid {@link DidMethodEnum} constants.
     */
    public static DidMethodEnum parse(String str) {
        if (str == null) {
            return null;
        }

        if (str.toLowerCase().equals(DidMethodEnum.TDW_0_3.asString())) {
            return DidMethodEnum.TDW_0_3;
        } else if (str.toLowerCase().equals(DidMethodEnum.WEBVH_1_0.asString())) {
            return DidMethodEnum.WEBVH_1_0;
        }

        throw new IllegalArgumentException("Unknown DID method: " + str);
    }

    public boolean isTdw03() {
        return false;
    }

    public boolean isWebVh10() {
        return false;
    }

    public String asString() {
        return didMethod;
    }
}