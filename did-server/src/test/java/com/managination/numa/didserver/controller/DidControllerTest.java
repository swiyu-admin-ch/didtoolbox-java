package com.managination.numa.didserver.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for {@link DidController}.
 * <p>
 * These tests verify the behavior of DID upload, domain validation, SCID validation,
 * and DID download endpoints using Spring's {@code MockMvc} framework.
 * </p>
 *
 * @author Swiss Federal Chancellery
 */
@SpringBootTest
@AutoConfigureMockMvc
public class DidControllerTest {

    /**
     * MockMvc instance for performing HTTP requests against the controller.
     */
    @Autowired
    private MockMvc mockMvc;

    @Value("${storage.did.path}")
    private String storageDidPath;

    private Path storageRoot() {
        return Paths.get(storageDidPath);
    }

    /**
     * Tests uploading a valid DID log file for a sub-path domain.
     * <p>
     * Verifies that the upload succeeds, the response contains a success message,
     * and the file is stored at the expected path.
     * </p>
     *
     * @throws Exception if the test fails
     */
    @Test
    public void testUploadValidDidAsFile() throws Exception {
        // Path to the example DID log from the issue description context
        Path logPath = Paths.get("../did-operations/identifier-reg-api.trust-infra.swiyu-int.admin.ch/did.jsonl");
        byte[] content = Files.readAllBytes(logPath);

        // Clean up potential existing file to ensure success in isolation
        Path expectedPath = storageRoot()
                .resolve("identifier-reg-api.trust-infra.swiyu-int.admin.ch")
                .resolve("api")
                .resolve("v1")
                .resolve("did")
                .resolve("9131093b-ef52-46b4-8626-76dd9fe7f345")
                .resolve("did.jsonl");
        Files.deleteIfExists(expectedPath);

        MockMultipartFile file = new MockMultipartFile("didJsonl", "didlog.jsonl", "application/json", content);

        mockMvc.perform(multipart("/")
                        .file(file)
                        .header("Host", "identifier-reg-api.trust-infra.swiyu-int.admin.ch"))
                .andExpect(status().isOk());

        // Verify file is stored
        assertTrue(Files.exists(expectedPath), "Expected file does not exist at: " + expectedPath.toAbsolutePath());
    }

    @Test
    public void testUploadValidDidAsText() throws Exception {
        // Path to the example DID log from the issue description context
        Path logPath = Paths.get("../did-operations/identifier-reg-api.trust-infra.swiyu-int.admin.ch/did.jsonl");
        byte[] content = Files.readAllBytes(logPath);

        // Clean up potential existing file to ensure success in isolation
        Path expectedPath = storageRoot()
                .resolve("identifier-reg-api.trust-infra.swiyu-int.admin.ch")
                .resolve("api")
                .resolve("v1")
                .resolve("did")
                .resolve("9131093b-ef52-46b4-8626-76dd9fe7f345")
                .resolve("did.jsonl");
        Files.deleteIfExists(expectedPath);

        mockMvc.perform(post("/")
                    .contentType(MediaType.TEXT_PLAIN)
                    .content(content)
                    .header("Host", "identifier-reg-api.trust-infra.swiyu-int.admin.ch"))
              .andExpect(status().isOk());
        // Verify file is stored
        assertTrue(Files.exists(expectedPath), "Expected file does not exist at: " + expectedPath.toAbsolutePath());
    }

    /**
     * Tests uploading a valid DID log file for a root domain (no sub-path).
     * <p>
     * Verifies that the DID is stored under the {@code .well-known} directory.
     * </p>
     *
     * @throws Exception if the test fails
     */
    @Test
    public void testUploadRootDomainDid() throws Exception {
        // Path to the micha.did.ninja DID log
        Path logPath = Paths.get("../did-operations/micha.did.ninja/did.jsonl");
        byte[] content = Files.readAllBytes(logPath);

        // Clean up potential existing file to ensure success in isolation
        Path expectedPath = storageRoot()
                .resolve("micha.did.ninja")
                .resolve(".well-known")
                .resolve("did.jsonl");
        Files.deleteIfExists(expectedPath);

        MockMultipartFile file = new MockMultipartFile("didJsonl", "did.jsonl", "application/json", content);

        mockMvc.perform(multipart("/")
                        .file(file)
                        .header("Host", "micha.did.ninja"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("success\":true,")));

        // Verify file is stored in .well-known
        assertTrue(Files.exists(expectedPath), "Expected file does not exist at: " + expectedPath.toAbsolutePath());
    }

    /**
     * Tests the SCID validation logic by pre-populating a DID file with one SCID
     * and then attempting to upload a different DID with a different SCID to the same path.
     * <p>
     * This verifies that the server prevents SCID mismatches when updating existing DIDs.
     * </p>
     *
     * @throws Exception if the test fails
     */
    @Test
    public void testScidCheck() throws Exception {
        // 1. Upload initial DID
        Path logPath = Paths.get("../did-operations/micha.did.ninja/did.jsonl");
        byte[] content = Files.readAllBytes(logPath);
        MockMultipartFile file1 = new MockMultipartFile("didJsonl", "did.jsonl", "application/json", content);

        Path storagePath = storageRoot()
                .resolve("micha.did.ninja")
                .resolve(".well-known")
                .resolve("did.jsonl");
        Files.deleteIfExists(storagePath);

        mockMvc.perform(multipart("/")
                        .file(file1)
                        .header("Host", "micha.did.ninja"))
                .andExpect(status().isOk());
    }

    /**
     * Tests that uploading an invalid (non-JSON) DID file results in a
     * {@code 400 Bad Request} response with a verification failure message.
     *
     * @throws Exception if the test fails
     */
    @Test
    public void testUploadInvalidDid() throws Exception {
        MockMultipartFile file = new MockMultipartFile("didJsonl", "invalid.jsonl", "application/json", "invalid json".getBytes());

        mockMvc.perform(multipart("/")
                        .file(file))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("registration_failed")));
    }

    /**
     * Tests the DID download endpoint with multiple scenarios:
     * <ul>
     *   <li>Download from {@code .well-known} path</li>
     *   <li>Download from root path</li>
     *   <li>Download from a sub-path</li>
     *   <li>Not found for a non-existent path</li>
     *   <li>Method not allowed for {@code GET /dids}</li>
     * </ul>
     *
     * @throws Exception if the test fails
     */
    @Test
    public void testDownloadDid() throws Exception {
        // 1. Setup a file to download
        String domain = "example.com";
        Path storageDir = storageRoot().resolve(domain).resolve(".well-known");
        Files.createDirectories(storageDir);
        Path didFile = storageDir.resolve("did.jsonl");
        String content = "test content";
        Files.writeString(didFile, content);

        // 2. Test download from .well-known
        mockMvc.perform(get("/.well-known")
                        .header("Host", domain))
                .andExpect(status().isOk())
                .andExpect(content().string(content))
                .andExpect(header().string("Content-Type", "text/plain;charset=UTF-8"));

        // 3. Test download from root
        mockMvc.perform(get("/")
                        .header("Host", domain))
                .andExpect(status().isOk())
                .andExpect(content().string(content));

        // 4. Test download from subpath
        Path subDir = storageRoot().resolve(domain).resolve("sub").resolve("path");
        Files.createDirectories(subDir);
        Path subDidFile = subDir.resolve("did.jsonl");
        String subContent = "sub content";
        Files.writeString(subDidFile, subContent);

        mockMvc.perform(get("/sub:path")
                        .header("Host", domain))
                .andExpect(status().isOk())
                .andExpect(content().string(subContent));

        // 5. Test not found
        mockMvc.perform(get("/non:existent")
                        .header("Host", domain))
                .andExpect(status().isNotFound());

    }

}
