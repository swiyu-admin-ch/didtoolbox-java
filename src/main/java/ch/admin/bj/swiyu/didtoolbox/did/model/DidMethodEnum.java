package ch.admin.bj.swiyu.didtoolbox.did.model;

import lombok.Getter;

import java.text.ParseException;

/**
 * The enumeration describing/modelling all the supported DID specifications
 */
public enum DidMethodEnum {
    /**
     * Refers to <a href="https://identity.foundation/didwebvh/v1.0/">The did:webvh DID Method v1.0</a>
     */
    WEBVH_1_0("webvh", "1.0");

    private final String didMethod;

    @Getter
    private final String prefix;

    private static final String DID_PREFIX = "did:";

    DidMethodEnum(String method, String version) {
        this.didMethod = DID_PREFIX + method + ":" + version;
        this.prefix = DID_PREFIX + method;
    }

    /**
     * A type conversion helper.
     *
     * @param str to convert to {@link DidMethodEnum} from. Case-insensitive.
     * @return a valid {@link DidMethodEnum} constant matching the supplied string. Otherwise, {@code null}.
     * @throws ParseException if the supplied string does not match any of the valid {@link DidMethodEnum} constants.
     */
    public static DidMethodEnum parse(String str) throws ParseException {
        if (str == null) {
            return null;
        }

        if (str.equalsIgnoreCase(DidMethodEnum.WEBVH_1_0.toString())) {
            return DidMethodEnum.WEBVH_1_0;
        }

        throw new ParseException("Unsupported or invalid DID method: " + str, 0);
    }

    @Override
    public String toString() {
        return this.didMethod;
    }
}