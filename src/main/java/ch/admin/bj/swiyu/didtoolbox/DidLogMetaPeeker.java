package ch.admin.bj.swiyu.didtoolbox;

import com.google.gson.Gson;

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

    static class DidLogMeta {

        private DidLogMeta() {
        }

        String lastVersionId;
        int lastVersionNumber;
        String dateTime;
        DidMethodParameters params;
        String didDocId;

        DidLogMeta(String lastVersionId, int lastVersionNumber, String dateTime, DidMethodParameters params, String didDocId) {
            this.lastVersionId = lastVersionId;
            this.lastVersionNumber = lastVersionNumber;
            this.dateTime = dateTime;
            this.params = params;
            this.didDocId = didDocId;
        }
    }

    /**
     * A helper storing the <a href="https://identity.foundation/didwebvh/v0.3/#didtdw-did-method-parameters">didtdw-did-method-parameters</a>.
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

        final static String METHOD_PARAM = "method";
        final static String SCID_PARAM = "scid";
        final static String UPDATE_KEYS_PARAM = "updateKeys";
        final static String DEACTIVATED_PARAM = "deactivated";

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

    /**
     * The essential method oh the helper class.
     *
     * @param didLog to peek into. It does not need to be necessarily "resolvable", however desirable.
     * @return metadata describing a DID log (to a certain extent).
     * @throws DidLogMetaPeekerException if peeking fails for whatever reason.
     */
    static DidLogMeta peek(String didLog) throws DidLogMetaPeekerException {

        AtomicReference<IOException> ioException = new AtomicReference<>();
        AtomicReference<String> lastVersionId = new AtomicReference<>();
        AtomicReference<String> dateTime = new AtomicReference<>();
        AtomicReference<DidMethodParameters> params = new AtomicReference<>();
        AtomicReference<String> didDocId = new AtomicReference<>();

        BufferedReader reader = new BufferedReader(new StringReader(didLog));

        reader.lines().forEach(line -> {

            var lineReader = new StringReader(line);
            var jsonReader = new Gson().newJsonReader(lineReader);
            jsonReader.setLenient(false); // default, use JsonReader.setLenient(true) to accept malformed JSON
            try { // NOTE that all jsonReader methods may throw IOException, which will be caught here
                while (jsonReader.hasNext()) {

                    jsonReader.beginArray(); // begin of entry (5-elements array)

                    lastVersionId.set(jsonReader.nextString());
                    dateTime.set(jsonReader.nextString());

                    jsonReader.beginObject(); // begin of params element

                    var buff = new StringBuilder();
                    while (jsonReader.hasNext()) {
                        var name = jsonReader.nextName();
                        // CAUTION Not all standard params are relevant here, as this class is focusing on just few
                        if (name.equals(DidMethodParameters.UPDATE_KEYS_PARAM)) {
                            jsonReader.beginArray();

                            buff.append("\"").append(name).append("\":[");
                            if (jsonReader.hasNext()) {
                                buff.append("\"").append(jsonReader.nextString()).append("\"");
                            }
                            while (jsonReader.hasNext()) {
                                buff.append(",\"").append(jsonReader.nextString()).append("\"");
                            }
                            buff.append("],");

                            jsonReader.endArray();
                        } else if (name.equals(DidMethodParameters.DEACTIVATED_PARAM)) {
                            buff.append("\"").append(name).append("\":").append(jsonReader.nextBoolean()).append(",");
                        } else if (name.equals(DidMethodParameters.METHOD_PARAM) || name.equals(DidMethodParameters.SCID_PARAM)) {
                            buff.append("\"").append(name).append("\":\"").append(jsonReader.nextString()).append("\",");
                        } else {
                            // Not all standard params are relevant here, as this class is focusing on just few
                            jsonReader.skipValue(); // skip the rest
                        }
                    }

                    jsonReader.endObject(); // end of params element

                    var json = "{" + buff.append("\"\":\"\"}");
                    var entryParams = (new Gson()).fromJson(json, DidMethodParameters.class);
                    if (params.get() == null) {
                        params.set(entryParams);
                    }
                    var x = params.get();
                    x.mergeFrom(entryParams);
                    params.set(x);

                    //jsonReader.skipValue(); // skip DID doc element, to prevent: java.lang.IllegalStateException: Expected END_ARRAY but was BEGIN_ARRAY

                    jsonReader.beginObject(); // begin of DID doc element
                    while (jsonReader.hasNext()) {
                        var name = jsonReader.nextName();
                        if (name.equals("value")) {
                            jsonReader.beginObject(); // begin of DID doc props

                            while (jsonReader.hasNext()) {
                                name = jsonReader.nextName();
                                if (name.equals("id")) {
                                    didDocId.set(jsonReader.nextString());
                                } else {
                                    // TODO to ignore or to throw en exception
                                    jsonReader.skipValue(); // skip the rest
                                }
                            }
                            jsonReader.endObject(); // end of DID doc props
                        } else {
                            // TODO to ignore or to throw en exception
                            jsonReader.skipValue(); // skip the rest
                        }
                    }

                    jsonReader.endObject(); // end of DID doc element

                    jsonReader.skipValue(); // skip proof element, to prevent: java.lang.IllegalStateException: Expected END_ARRAY but was BEGIN_ARRAY

                    jsonReader.endArray(); // end of entry
                }
            } catch (IOException e) {
                ioException.set(e);
            } finally {
            }

            lineReader.close();
        });

        try {
            reader.close();
        } catch (IOException ignore) {
            //
        }

        if (ioException.get() != null) {
            throw new DidLogMetaPeekerException("Malformed DID log entry", ioException.get());
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

        return new DidLogMeta(lastVersionId.get(), lastVersionNumber, dateTime.get(), params.get(), didDocId.get());
    }
}
