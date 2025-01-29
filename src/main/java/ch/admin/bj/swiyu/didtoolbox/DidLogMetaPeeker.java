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

        /*
        JsonObject paramsAsJsonObject(){

            var obj = new JsonObject();
            obj.addProperty("method", this.params.method);
            obj.addProperty("scid", this.lastVersionId);

            if (this.params.updateKeys != null && !this.params.updateKeys.isEmpty()) {
                var updateKeys = new JsonArray();
                this.params.updateKeys.forEach(updateKeys::add);
                obj.add("updateKeys", updateKeys);
            }

            if (this.params.nextKeyHashes != null && !this.params.nextKeyHashes.isEmpty()) {
                var nextKeyHashes = new JsonArray();
                this.params.nextKeyHashes.forEach(nextKeyHashes::add);
                obj.add("nextKeyHashes", nextKeyHashes);
            }

            if (this.params.witnesses != null && !this.params.witnesses.isEmpty()) {
                var witnesses = new JsonArray();
                this.params.witnesses.forEach(witnesses::add);
                obj.add("witnesses", witnesses);
            }

            if (this.params.witnessThreshold != null) {
                obj.addProperty("witnessThreshold", this.params.witnessThreshold);
            }
            if (this.params.deactivated != null) {
                obj.addProperty("deactivated", this.params.deactivated);
            }
            if (this.params.portable != null) {
                obj.addProperty("portable", this.params.portable);
            }
            if (this.params.prerotation != null) {
                obj.addProperty("prerotation", this.params.prerotation);
            }

            return obj;
        }
         */
    }

    // According to https://identity.foundation/didwebvh/v0.3/#didtdw-did-method-parameters
    static class DidMethodParameters {
        String method;
        String scid;
        // Since v0.3 (https://identity.foundation/trustdidweb/v0.3/#didtdw-version-changelog):
        //            Removes the cryptosuite parameter, moving it to implied based on the method parameter.
        /*
        String cryptosuite;
         */
        Boolean prerotation;
        List<String> updateKeys;
        List<String> nextKeyHashes;
        List<String> witnesses;
        Integer witnessThreshold;
        //String moved;
        Boolean deactivated;
        //int ttl;
        Boolean portable;

        void mergeFrom(DidMethodParameters other){
            if (other.method != null && !other.method.isEmpty()){
                this.method = other.method;
            }
            if (other.scid != null && !other.scid.isEmpty()){
                this.scid = other.scid;
            }
            if (other.prerotation != null){
                this.prerotation = other.prerotation;
            }
            if (other.updateKeys != null && !other.updateKeys.isEmpty()){
                this.updateKeys = other.updateKeys;
            }
            if (other.nextKeyHashes != null && !other.nextKeyHashes.isEmpty()){
                this.nextKeyHashes = other.nextKeyHashes;
            }
            if (other.witnesses != null && !other.witnesses.isEmpty()){
                this.witnesses = other.witnesses;
            }
            if (other.witnessThreshold != null){
                this.witnessThreshold = other.witnessThreshold;
            }
            if (other.deactivated != null){
                this.deactivated = other.deactivated;
            }
            if (other.portable != null){
                this.portable = other.portable;
            }
        }
    }

    /**
     * The essential method oh the helper class.
     *
     * @param didLog
     * @return
     * @throws DidLogMetaPeekerException
     */
    static DidLogMeta peek(String didLog) throws DidLogMetaPeekerException {

        AtomicReference<IOException> ioException = new AtomicReference<>();
        AtomicReference<String> lastVersionId = new AtomicReference<>();
        AtomicReference<String> dateTime = new AtomicReference<>();
        //AtomicReference<List<String>> updateKeys = new AtomicReference<>();
        AtomicReference<DidMethodParameters> params = new AtomicReference<>();
        AtomicReference<String> didDocId = new AtomicReference<>();

        BufferedReader reader = new BufferedReader(new StringReader(didLog));

        reader.lines().forEach(line -> {

            var lineReader = new StringReader(line);
            var jsonReader = new Gson().newJsonReader(lineReader);
            jsonReader.setLenient(false); // default, use JsonReader.setLenient(true) to accept malformed JSON
            try { // note that all jsonReader methods may throw IOException, which will be captured
                while (jsonReader.hasNext()) {

                    jsonReader.beginArray(); // begin of entry (5-elements array)

                    lastVersionId.set(jsonReader.nextString());
                    dateTime.set(jsonReader.nextString());

                    jsonReader.beginObject(); // begin of params element

                    var buff = new StringBuilder();
                    while (jsonReader.hasNext()) {
                        var name = jsonReader.nextName();
                        if (name.equals("updateKeys") || name.equals("nextKeyHashes") || name.equals("witnesses")) {
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
                        } else if (name.equals("portable") || name.equals("prerotation") || name.equals("deactivated")) {
                            buff.append("\"").append(name).append("\":").append(jsonReader.nextBoolean()).append(",");
                        } else if (name.equals("witnessThreshold")) {
                            buff.append("\"").append(name).append("\":").append(jsonReader.nextInt()).append(",");
                        } else if (name.equals("method") || name.equals("scid")) {
                            buff.append("\"").append(name).append("\":\"").append(jsonReader.nextString()).append("\",");
                        } else {
                            // TODO to ignore or to throw en exception
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
