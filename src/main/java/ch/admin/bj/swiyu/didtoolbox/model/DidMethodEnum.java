package ch.admin.bj.swiyu.didtoolbox.model;

import lombok.Getter;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.text.ParseException;

/**
 * The enumeration describing/modelling all the supported DID specifications
 */
public enum DidMethodEnum {
    /**
     * Refers to <a href="https://identity.foundation/didwebvh/v0.3/">Trust DID Web - did:tdw - v0.3</a>
     */
    TDW_0_3("tdw", "0.3") {
        @Override
        public boolean isTdw03() {
            return true;
        }
    },
    /**
     * Refers to <a href="https://identity.foundation/didwebvh/v1.0/">The did:webvh DID Method v1.0</a>
     */
    WEBVH_1_0("webvh", "1.0") {
        @Override
        public boolean isWebVh10() {
            return true;
        }
    };

    /**
     * String representation of {@link DidMethodEnum#TDW_0_3}
     */
    @Deprecated(since = "2.2.0")
    public static final String TDW_0_3_STRING = "did:tdw:0.3";

    /**
     * String representation of {@link DidMethodEnum#WEBVH_1_0}
     */
    @Deprecated(since = "2.2.0")
    public static final String WEBVH_1_0_STRING = "did:webvh:1.0";

    private final String didMethod;
    @Getter
    private final String prefix;

    private static final String DID_PREFIX = "did:";

    DidMethodEnum(String method, String version) {
        this.didMethod = DID_PREFIX + method + ":" + version;
        this.prefix = DID_PREFIX + method;
    }

    /**
     * Yet another type conversion helper.
     *
     * @param str to convert to {@link DidMethodEnum} from. Case-insensitive.
     * @return a valid {@link DidMethodEnum} constant matching the supplied string. Otherwise, {@code null}.
     * @throws ParseException if the supplied string does not match any of the valid {@link DidMethodEnum} constants.
     */
    public static DidMethodEnum parse(String str) throws ParseException {
        if (str == null) {
            return null;
        }

        if (str.equalsIgnoreCase(DidMethodEnum.TDW_0_3.toString())) {
            return DidMethodEnum.TDW_0_3;
        } else if (str.equalsIgnoreCase(DidMethodEnum.WEBVH_1_0.toString())) {
            return DidMethodEnum.WEBVH_1_0;
        }

        throw new ParseException("Unknown or unsupported DID method: " + str, 0);
    }

    @Deprecated(since = "2.3.0")
    public boolean isTdw03() {
        return false;
    }

    @Deprecated(since = "2.3.0")
    public boolean isWebVh10() {
        return false;
    }

    @Deprecated(since = "2.2.0")
    public String asString() {
        return this.toString();
    }

    @Override
    public String toString() {
        return this.didMethod;
    }

    public static DidMethodEnum detectDidMethod(File didLogFile) throws DidLogMetaPeekerException, IOException {
        return detectDidMethod(Files.readString(didLogFile.toPath()));
    }

    @SuppressWarnings("PMD.PreserveStackTrace")
    public static DidMethodEnum detectDidMethod(String didLog) throws DidLogMetaPeekerException {
        DidLogMeta didLogMeta;
        try {
            didLogMeta = TdwDidLogMetaPeeker.peek(didLog); // assume a did:tdw log
        } catch (DidLogMetaPeekerException ignore) { // not a did:tdw log
            try {
                didLogMeta = WebVerifiableHistoryDidLogMetaPeeker.peek(didLog); // assume a did:webvh log
            } catch (DidLogMetaPeekerException exc) { // not a did:webvh log
                throw new DidLogMetaPeekerException("The supplied DID log features an unsupported DID method", exc);
            }
        }

        if (didLogMeta.getParams() == null || didLogMeta.getParams().getDidMethodEnum() == null) {
            throw new DidLogMetaPeekerException("Incomplete metadata");
        }

        return didLogMeta.getParams().getDidMethodEnum();
    }
}