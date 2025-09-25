package ch.admin.bj.swiyu.didtoolbox.model;

import ch.admin.bj.swiyu.didtoolbox.TdwUpdater;
import ch.admin.eid.did_sidekicks.DidDoc;
import ch.admin.eid.did_sidekicks.DidMethodParameter;
import ch.admin.eid.didresolver.Did;
import ch.admin.eid.didresolver.DidResolveException;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import lombok.Getter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A quite rudimentary did:tdw DID log entry parser intended as a sidekick (helper) of {@link TdwUpdater}.
 */
public final class TdwDidLogMetaPeeker {

    private TdwDidLogMetaPeeker() {
    }

    /**
     * The essential method oh the helper class.
     *
     * @param didLog to peek into. It is assumed a "resolvable" {@link DidMethodEnum#TDW_0_3}-conform DID log is supplied.
     * @return metadata describing a DID log (to a certain extent).
     * @throws DidLogMetaPeekerException if "peeking" failed for whatever reason.
     *                                   The {@link MalformedTdwDidLogMetaPeekerException} variant
     *                                   if thrown in case a fully malformed DID log (in terms of specification) was supplied
     */
    @SuppressWarnings({"PMD.CognitiveComplexity", "PMD.CyclomaticComplexity"})
    public static DidLogMeta peek(String didLog) throws DidLogMetaPeekerException {

        AtomicReference<Exception> jsonSyntaxEx = new AtomicReference<>();
        AtomicReference<String> lastVersionId = new AtomicReference<>();
        AtomicReference<String> dateTime = new AtomicReference<>();
        AtomicReference<String> didDocId = new AtomicReference<>();

        // CAUTION Trimming the existing DID log prevents ending up parsing empty lines
        BufferedReader reader = new BufferedReader(new StringReader(didLog.trim()));

        AtomicReference<Object[]> didLogEntryElements = new AtomicReference<>();
        reader.lines().takeWhile(line -> {
            try {
                didLogEntryElements.set(new Gson().fromJson(line, Object[].class)); // may throw JsonSyntaxException
            } catch (JsonSyntaxException e) {
                jsonSyntaxEx.set(e);
                return false; // short-circuit the stream
            }

            if (didLogEntryElements.get().length != 5) {
                jsonSyntaxEx.set(new JsonSyntaxException("Expected at 5 DID log entry elements but got " + didLogEntryElements.get().length));
                return false; // short-circuit the stream
            }

            return true;

        }).forEach(ignored -> { // CAUTION The string var is ignored here, as the DID log entry deserialisation has already been done earlier by takeWhile

            var lastVersionIdObj = didLogEntryElements.get()[0];
            if (lastVersionIdObj == null) {
                jsonSyntaxEx.set(new JsonSyntaxException("The first DID log entry element (`versionId`) is missing"));
                return;
            }
            lastVersionId.set(lastVersionIdObj.toString());

            var dateTimeObj = didLogEntryElements.get()[1];
            if (dateTimeObj == null) {
                jsonSyntaxEx.set(new JsonSyntaxException("The second DID log entry element (`dateTime`) is missing"));
                return;
            }
            dateTime.set(dateTimeObj.toString());

            var parametersObj = didLogEntryElements.get()[2];
            if (parametersObj == null) {
                jsonSyntaxEx.set(new JsonSyntaxException("The third DID log entry element (`parameters`) is missing"));
                return;
            }
            // CAUTION Skip parsing the parameters (didLogEntryElements.get()[2]), as they will be supplied by the resolver afterwards

            var didDocObj = didLogEntryElements.get()[3];
            if (didDocObj == null) {
                jsonSyntaxEx.set(new JsonSyntaxException("The forth DID log entry element (`DIDDoc State`) is missing"));
                return;
            }

            var gson = new Gson();

            DidDocValue didDocValue;
            try {
                didDocValue = gson.fromJson(gson.toJson(didDocObj), DidDocValue.class);
            } catch (JsonSyntaxException ex) {
                jsonSyntaxEx.set(ex);
                return;
            }
            if (didDocValue != null && didDocValue.getValue() != null) {
                didDocId.set(didDocValue.getValue().getId());
            }
        });

        try {
            reader.close();
        } catch (IOException ignore) {
            //
        }

        if (jsonSyntaxEx.get() != null) {
            throw new MalformedTdwDidLogMetaPeekerException("Malformed " + DidMethodEnum.TDW_0_3.asString() + " log entry (a JSON array expected)", jsonSyntaxEx.get());
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

        if (didDocId.get() == null) {
            throw new DidLogMetaPeekerException("DID doc ID missing");
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

    @Getter
    static class DidDocValue {
        DidDocument value;
    }
}
