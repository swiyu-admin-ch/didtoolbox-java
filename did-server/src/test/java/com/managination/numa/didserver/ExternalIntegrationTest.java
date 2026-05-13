package com.managination.numa.didserver;

import ch.admin.bj.swiyu.didtoolbox.JwkUtils;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorContext;
import ch.admin.bj.swiyu.didtoolbox.model.VerificationMethod;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import org.junit.jupiter.api.Test;

import javax.net.ssl.HttpsURLConnection;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class ExternalIntegrationTest {

    static String createDid(String didDomain) throws Exception {
        var cryptoSuite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite();

        Path tempDir = Files.createTempDirectory("did-test-keys");
        Path authKeyPath = tempDir.resolve("auth-ec.pem");
        Path assertKeyPath = tempDir.resolve("assert-ec.pem");

        try {
            JwkUtils.generatePublicEC256("auth-0", authKeyPath.toFile(), true);
            JwkUtils.generatePublicEC256("assert-0", assertKeyPath.toFile(), true);

            URI identifierRegistryUri = URI.create("https://" + didDomain + "/.well-known/did.jsonl");

            return DidLogCreatorContext.builder()
                    .cryptographicSuite(cryptoSuite)
                    .assertionMethods(Set.of(VerificationMethod.of("assert-0", Path.of(assertKeyPath + ".pub"))))
                    .authentications(Set.of(VerificationMethod.of("auth-0", Path.of(authKeyPath + ".pub"))))
                    .build()
                    .create(identifierRegistryUri.toURL());
        } finally {
            Files.deleteIfExists(authKeyPath);
            Files.deleteIfExists(Path.of(authKeyPath + ".pub"));
            Files.deleteIfExists(assertKeyPath);
            Files.deleteIfExists(Path.of(assertKeyPath + ".pub"));
            Files.deleteIfExists(tempDir);
        }
    }

    private static String readResponse(HttpsURLConnection conn) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line);
        }
        reader.close();
        return sb.toString();
    }

    private static String readErrorStream(HttpsURLConnection conn) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getErrorStream()));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line);
        }
        reader.close();
        return sb.toString();
    }

    @Test
    void testRegisterAndRetrieveDid() throws Exception {
        byte[] randomBytes = new byte[4];
        SecureRandom.getInstanceStrong().nextBytes(randomBytes);
        String randomHex = HexFormat.of().formatHex(randomBytes);
        String didDomain = "micha-" + randomHex + ".test.did.ninja";
        String url = "https://" + didDomain;

        String didJsonl = createDid(didDomain);

        URI registerUri = URI.create(url + "/");
        HttpsURLConnection registerConn = (HttpsURLConnection) registerUri.toURL().openConnection();
        registerConn.setRequestMethod("POST");
        registerConn.setRequestProperty("Host", didDomain);
        registerConn.setRequestProperty("Content-Type", "application/jsonl");
        registerConn.setDoOutput(true);
        registerConn.setInstanceFollowRedirects(true);

        try (OutputStream os = registerConn.getOutputStream()) {
            os.write(didJsonl.getBytes(StandardCharsets.UTF_8));
            os.flush();
        }

        int registerStatus = registerConn.getResponseCode();
        String registerBody = (registerStatus == 200) ? readResponse(registerConn) : readErrorStream(registerConn);
        registerConn.disconnect();

        assertEquals(200, registerStatus,
                "Registration should succeed with HTTP 200. Got " + registerStatus + ": " + registerBody);
        assertTrue(registerBody.contains("\"success\":true"),
                "Response body should indicate success: " + registerBody);

        URI retrieveUri = URI.create(url + "/.well-known");
        HttpsURLConnection retrieveConn = (HttpsURLConnection) retrieveUri.toURL().openConnection();
        retrieveConn.setRequestMethod("GET");
        retrieveConn.setRequestProperty("Host", didDomain);
        retrieveConn.setInstanceFollowRedirects(true);

        int retrieveStatus = retrieveConn.getResponseCode();
        String retrieveBody = (retrieveStatus == 200) ? readResponse(retrieveConn) : readErrorStream(retrieveConn);
        retrieveConn.disconnect();

        assertEquals(200, retrieveStatus,
                "Retrieval should succeed with HTTP 200. Got " + retrieveStatus + ": " + retrieveBody);

        String retrievedNormalized = retrieveBody.replaceAll("\\r?\\n", "");
        String expectedNormalized = didJsonl.replaceAll("\\r?\\n", "");
        assertEquals(expectedNormalized, retrievedNormalized,
                "Retrieved DID log should match the registered one");
    }
}
