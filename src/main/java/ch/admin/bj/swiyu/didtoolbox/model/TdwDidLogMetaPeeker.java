package ch.admin.bj.swiyu.didtoolbox.model;

import ch.admin.bj.swiyu.didtoolbox.TdwUpdater;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A quite rudimentary did:tdw DID log entry parser intended as a sidekick (helper) of {@link TdwUpdater}.
 */
public class TdwDidLogMetaPeeker {

    private TdwDidLogMetaPeeker() {
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
        AtomicReference<String> didDocId = new AtomicReference<>();

        // CAUTION Trimming the existing DID log prevents ending up parsing empty lines
        BufferedReader reader = new BufferedReader(new StringReader(didLog.trim()));

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

                var didDocValue = gson.fromJson(gson.toJson(didLogEntryElements[3]), DidDocValue.class);
                if (didDocValue != null && didDocValue.value != null) {
                    didDocId.set(didDocValue.value.getId());
                }

                var proof = gson.fromJson(gson.toJson(didLogEntryElements[4]), DataIntegrityProof[].class);
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

        if (params.get() == null) {
            throw new DidLogMetaPeekerException("Missing parameters");
        }

        if (params.get().method == null || params.get().method.isEmpty() || !params.get().method.startsWith(DidMethodEnum.TDW_0_3.getPrefix())) {
            throw new DidLogMetaPeekerException("The 'method' DID parameter MUST be one of the supported '" + DidMethodEnum.TDW_0_3.getPrefix() + "' versions");
        }

        /*
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

        return new DidLogMeta(lastVersionId.get(), lastVersionNumber, dateTime.get(), params.get(), null, didDocId.get());
    }

    static class DidDocValue {
        DidDocument value;
    }
}
