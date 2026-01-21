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

    /**
     * String representation of {@link DidMethodEnum#TDW_0_3}
     */
    public final static String TDW_0_3_STRING = "did:tdw:0.3";

    /**
     * String representation of {@link DidMethodEnum#WEBVH_1_0}
     */
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
     * @return a valid {@link DidMethodEnum} constant matching the supplied string. Otherwise, {@code null}.
     * @throws ParseException if the supplied string does not match any of the valid {@link DidMethodEnum} constants.
     */
    public static DidMethodEnum parse(String str) throws ParseException {
        if (str == null) {
            return null;
        }

        if (str.toLowerCase().equals(DidMethodEnum.TDW_0_3.asString())) {
            return DidMethodEnum.TDW_0_3;
        } else if (str.toLowerCase().equals(DidMethodEnum.WEBVH_1_0.asString())) {
            return DidMethodEnum.WEBVH_1_0;
        }

        throw new ParseException("Unknown or unsupported DID method: " + str, 0);
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

    public static DidMethodEnum detectDidMethod(File didLogFile) throws DidLogMetaPeekerException, IOException {
        return detectDidMethod(Files.readString(didLogFile.toPath()));
    }

    public static DidMethodEnum detectDidMethod(String didLog) throws DidLogMetaPeekerException {
        DidLogMeta didLogMeta;
        try {
            didLogMeta = TdwDidLogMetaPeeker.peek(didLog); // assume a did:tdw log
        } catch (DidLogMetaPeekerException exc) { // not a did:tdw log
            try {
                didLogMeta = WebVerifiableHistoryDidLogMetaPeeker.peek(didLog); // assume a did:webvh log
            } catch (DidLogMetaPeekerException ex) { // not a did:webvh log
                throw new DidLogMetaPeekerException("The supplied DID log features an unsupported DID method", ex);
            }
        }

        if (didLogMeta.getParams() == null || didLogMeta.getParams().getDidMethodEnum() == null) {
            throw new DidLogMetaPeekerException("Incomplete metadata");
        }

        return didLogMeta.getParams().getDidMethodEnum();
    }
}