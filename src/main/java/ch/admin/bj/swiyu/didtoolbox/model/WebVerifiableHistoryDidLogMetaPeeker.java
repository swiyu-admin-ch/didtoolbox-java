package ch.admin.bj.swiyu.didtoolbox.model;

import ch.admin.bj.swiyu.didtoolbox.TdwUpdater;
import ch.admin.eid.did_sidekicks.DidDoc;
import ch.admin.eid.did_sidekicks.DidMethodParameter;
import ch.admin.eid.didresolver.Did;
import ch.admin.eid.didresolver.DidResolveException;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.annotations.SerializedName;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A quite rudimentary did:webvh DID log entry parser intended as a sidekick (helper) of {@link TdwUpdater}.
 */
public class WebVerifiableHistoryDidLogMetaPeeker {

    private WebVerifiableHistoryDidLogMetaPeeker() {
    }

    static class WebVhDidLogEntry {
        String versionId;
        String versionTime;

        // Skip parsing the "parameters", as they will be supplied by the resolver afterwards


        @SerializedName("state")
        DidDocument didDocument;
        DataIntegrityProof[] proof;
    }

    /**
     * The essential method oh the helper class.
     *
     * @param didLog to peek into. It is assumed a "resolvable" {@link DidMethodEnum#WEBVH_1_0}-conform DID log is supplied.
     * @return metadata describing a DID log (to a certain extent).
     * @throws DidLogMetaPeekerException if "peeking" failed for whatever reason.
     *                                   The {@link MalformedWebVerifiableHistoryDidLogMetaPeekerException} variant
     *                                   if thrown in case a fully malformed DID log (in terms of specification) was supplied
     */
    public static DidLogMeta peek(String didLog) throws DidLogMetaPeekerException {

        AtomicReference<Exception> jsonSyntaxEx = new AtomicReference<>();
        AtomicReference<String> lastVersionId = new AtomicReference<>();
        AtomicReference<String> dateTime = new AtomicReference<>();
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

                // Skip parsing the parameters (didLogEntryElements[2]), as they will be supplied by the resolver afterwards

                var didDocument = didLogEntry.didDocument;
                if (didDocument != null && didDocument.getId() != null) {
                    //didDoc.set(didDocument);
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
            throw new MalformedWebVerifiableHistoryDidLogMetaPeekerException("Malformed " + DidMethodEnum.WEBVH_1_0.asString() + " log entry (a JSON object expected)", jsonSyntaxEx.get());
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

        if (didDocId.get() == null) {
            throw new DidLogMetaPeekerException("Missing DID document");
        }

        if (proof.get() == null) {
            throw new DidLogMetaPeekerException("Missing DID integrity proof");
        }

        DidDoc didDoc;
        Map<String, DidMethodParameter> didMethodParameters;
        try {
            var resolveAll = new Did(didDocId.get()).resolveAll(didLog);
            didDoc = resolveAll.getDidDoc();
            didMethodParameters = resolveAll.getDidMethodParameters();
        } catch (DidResolveException e) {
            throw new DidLogMetaPeekerException(e);
        }

        return new DidLogMeta(lastVersionId.get(), lastVersionNumber, dateTime.get(), didMethodParameters, didDoc);
    }
}
