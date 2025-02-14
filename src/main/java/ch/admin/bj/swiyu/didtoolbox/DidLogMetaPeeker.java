package ch.admin.bj.swiyu.didtoolbox;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A quite rudimentary DID log parser intended as a sidekick (helper) of {@link TdwUpdater}.
 */
class DidLogMetaPeeker {

    private DidLogMetaPeeker() {
    }

    /**
     * The essential method oh the helper class.
     *
     * @param didLog to peek into. It does not need to be necessarily "resolvable", however desirable.
     * @return metadata describing a DID log (to a certain extent).
     * @throws DidLogMetaPeekerException if peeking fails for whatever reason.
     */
    static DidLogMeta peek(String didLog) throws DidLogMetaPeekerException {

        AtomicReference<Exception> jsonSyntaxEx = new AtomicReference<>();
        AtomicReference<String> lastVersionId = new AtomicReference<>();
        AtomicReference<String> dateTime = new AtomicReference<>();
        AtomicReference<DidMethodParameters> params = new AtomicReference<>();
        AtomicReference<String> didDocId = new AtomicReference<>();

        BufferedReader reader = new BufferedReader(new StringReader(didLog));

        reader.lines().forEach(line -> {

            var gson = new Gson();

            try {
                Object[] didLogEntryElements = gson.fromJson(line, Object[].class);
                if (didLogEntryElements.length != 5) {
                    throw new JsonSyntaxException("Expected at 5 DID log entry elements but got " + didLogEntryElements.length);
                }

                lastVersionId.set(didLogEntryElements[0].toString());
                dateTime.set(didLogEntryElements[1].toString());

                var entryParams = gson.fromJson(gson.toJson(didLogEntryElements[2]), DidMethodParameters.class);
                if (entryParams != null) {
                    if (params.get() == null) {
                        params.set(entryParams);
                    }
                    var x = params.get();
                    x.mergeFrom(entryParams);
                    params.set(x);
                }

                var didDoc = gson.fromJson(gson.toJson(didLogEntryElements[3]), DidDocValue.class);
                if (didDoc != null && didDoc.value != null) {
                    didDocId.set(didDoc.value.id);
                }

                var proof = gson.fromJson(gson.toJson(didLogEntryElements[4]), Object.class);
                if (proof == null) {
                    throw new JsonSyntaxException("Proof is missing");
                }

            } catch (JsonSyntaxException e) {
                jsonSyntaxEx.set(e);
            } finally {
            }
        });

        try {
            reader.close();
        } catch (IOException ignore) {
            //
        }

        if (jsonSyntaxEx.get() != null) {
            throw new DidLogMetaPeekerException("Malformed DID log entry", jsonSyntaxEx.get());
        }

        var split = lastVersionId.get().split("-");
        if (split.length != 2) {
            throw new DidLogMetaPeekerException("Every versionId MUST be a dash-separated combination of version number and entry hash, found: " + lastVersionId.get());
        }
        int lastVersionNumber;
        try {
            lastVersionNumber = Integer.parseInt(split[0]);
        } catch (NumberFormatException e) {
            throw new DidLogMetaPeekerException("Invalid DID log entry version number: " + split[0], e);
        }

        if (dateTime.get().isEmpty()) {
            throw new DidLogMetaPeekerException("The versionTime MUST be a valid ISO8601 date/time string");
        }

        /*
        if (params.get().method == null || params.get().method.isEmpty()) {
            throw new DidLogMetaPeekerException("The 'method' DID parameter MUST be set");
        }

        if (params.get().scid == null || params.get().scid.isEmpty()) {
            throw new DidLogMetaPeekerException("The SCID DID parameter MUST be set");
        }

        if (params.get().updateKeys == null || params.get().updateKeys.isEmpty()) {
            throw new DidLogMetaPeekerException("The updateKeys DID parameter MUST not be empty");
        }
         */

        if (didDocId.get() == null) {
            throw new DidLogMetaPeekerException("DID doc ID missing");
        }

        return new DidLogMeta(lastVersionId.get(), lastVersionNumber, dateTime.get(), params.get(), didDocId.get());
    }

    static class DidLogMeta {

        String lastVersionId;
        int lastVersionNumber;
        String dateTime;
        DidMethodParameters params;
        String didDocId;

        private DidLogMeta() {
        }

        DidLogMeta(String lastVersionId, int lastVersionNumber, String dateTime, DidMethodParameters params, String didDocId) {
            this.lastVersionId = lastVersionId;
            this.lastVersionNumber = lastVersionNumber;
            this.dateTime = dateTime;
            this.params = params;
            this.didDocId = didDocId;
        }
    }

    /**
     * The helper storing a <a href="https://identity.foundation/didwebvh/v0.3/#didtdw-did-method-parameters">didtdw-did-method-parameters</a>.
     * <p>
     * However, not all standard params are relevant here, as this class is focusing on quite a few of them such as:
     * <ul>
     *     <li>method</li>
     *     <li>scid</li>
     *     <li>updateKeys</li>
     *     <li>deactivated</li>
     * </ul>
     */
    static class DidMethodParameters {

        String method;
        String scid;
        List<String> updateKeys;
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

    static class DidDocValue {
        DidDoc value;
    }

    /**
     * A helper storing the <a href="https://www.w3.org/TR/did-1.0/#core-properties">DID Document core-properties</a>.
     * <p>
     * However, not all standard props are relevant here, as this class is focusing on quite a few of them such as:
     * <ul>
     *     <li>id</li>
     * </ul>
     */
    static class DidDoc {
        String id;
    }
}
