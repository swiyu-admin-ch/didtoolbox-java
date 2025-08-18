package ch.admin.bj.swiyu.didtoolbox.model;

import ch.admin.bj.swiyu.didtoolbox.TdwUpdater;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.annotations.SerializedName;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A quite rudimentary did:webvh DID log entry parser intended as a sidekick (helper) of {@link TdwUpdater}.
 */
public class WebVhDidLogMetaPeeker {

    private WebVhDidLogMetaPeeker() {
    }

    static class WebVhDidLogEntry {
        String versionId;
        String versionTime;
        DidMethodParameters parameters;
        @SerializedName("state")
        DidDocument didDocument;
        DataIntegrityProof[] proof;
    }

    /**
     * The essential method oh the helper class.
     *
     * @param didLog to peek into. It does not need to be necessarily "resolvable", however desirable.
     * @return metadata describing a DID log (to a certain extent).
     * @throws DidLogMetaPeekerException if peeking fails for whatever reason.
     */
    public static DidLogMeta peek(String didLog) throws DidLogMetaPeekerException {

        AtomicReference<Exception> jsonSyntaxEx = new AtomicReference<>();
        AtomicReference<String> lastVersionId = new AtomicReference<>();
        AtomicReference<String> dateTime = new AtomicReference<>();
        AtomicReference<DidMethodParameters> params = new AtomicReference<>();
        AtomicReference<DidDocument> didDoc = new AtomicReference<>();
        AtomicReference<String> didDocId = new AtomicReference<>();
        AtomicReference<DataIntegrityProof[]> proof = new AtomicReference<>();

        // CAUTION Trimming the existing DID log prevents ending up parsing empty lines
        BufferedReader reader = new BufferedReader(new StringReader(didLog.trim()));

        reader.lines().forEach(line -> {

            var gson = new Gson();

            try {
                var didLogEntry = gson.fromJson(line, WebVhDidLogEntry.class);

                lastVersionId.set(didLogEntry.versionId);
                dateTime.set(didLogEntry.versionTime);

                var entryParams = didLogEntry.parameters;
                if (entryParams != null) {
                    if (params.get() == null) {
                        params.set(entryParams);
                    }
                    var x = params.get();
                    x.mergeFrom(entryParams);
                    params.set(x);
                }

                var didDocument = didLogEntry.didDocument;
                if (didDocument != null && didDocument.getId() != null) {
                    didDoc.set(didDocument);
                    didDocId.set(didDocument.getId());
                }

                if (didLogEntry.proof != null) {
                    proof.set(didLogEntry.proof);
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

        if (lastVersionId.get() == null) {
            throw new DidLogMetaPeekerException("Missing versionId");
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

        if (dateTime.get() == null) {
            throw new DidLogMetaPeekerException("Missing versionTime");
        }

        if (dateTime.get().isEmpty()) {
            throw new DidLogMetaPeekerException("The versionTime MUST be a valid ISO8601 date/time string");
        }

        if (params.get() == null) {
            throw new DidLogMetaPeekerException("Missing parameters");
        }

        if (params.get().method == null || params.get().method.isEmpty() || !params.get().method.startsWith("did:webvh:")) {
            throw new DidLogMetaPeekerException("The 'method' DID parameter MUST be set to 'did:webvh:<VERSION>'");
        }

        if (params.get().scid == null || params.get().scid.isEmpty()) {
            throw new DidLogMetaPeekerException("The SCID DID parameter MUST be set");
        }

        if (params.get().updateKeys == null || params.get().updateKeys.isEmpty()) {
            throw new DidLogMetaPeekerException("The updateKeys DID parameter MUST not be empty");
        }

        if (didDocId.get() == null) {
            throw new DidLogMetaPeekerException("Missing DID document");
        }

        if (proof.get() == null) {
            throw new DidLogMetaPeekerException("Missing DID integrity proof");
        }

        return new DidLogMeta(lastVersionId.get(), lastVersionNumber, dateTime.get(), params.get(), didDoc.get(), didDocId.get());
    }
}
