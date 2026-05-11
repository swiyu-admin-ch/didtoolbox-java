package com.managination.numa.didserver.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.managination.numa.didserver.dto.*;
import com.managination.numa.didserver.model.DidDocument;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class DidServiceTest {

    private DidService didService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        didService = new DidService();
        didService.init();
    }

    @Test
    void testGetHealthStatus() {
        HealthStatus health = didService.getHealthStatus();

        assertNotNull(health);
        assertNotNull(health.status());
        assertNotNull(health.timestamp());
        assertNotNull(health.filesystem());
        assertNotNull(health.memory());
        assertNotNull(health.jvm());
        assertNotNull(health.environment());
    }

    @Test
    void testGetServerPublicKey() {
        ServerPublicKeyResponse response = didService.getServerPublicKey();

        assertNotNull(response);
        assertNotNull(response.publicKey());
        assertEquals("ES256", response.algorithm());
        assertNotNull(response.keyId());
        assertNotNull(response.rotatedAt());
    }

    @Test
    void testRegisterDidWithProofJsonl() throws Exception {
        String resourcePath = "/example-with-proof.jsonl";
        Map<String, Object> logEntry;
        String didJsonl;
        try (InputStream is = getClass().getResourceAsStream(resourcePath)) {
            assertNotNull(is, "Resource not found: " + resourcePath);
            logEntry = objectMapper.readValue(is, Map.class);
            didJsonl = objectMapper.writeValueAsString(logEntry);
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> state = (Map<String, Object>) logEntry.get("state");
        assertNotNull(state, "Log entry must contain 'state'");

        String did = (String) state.get("id");
        assertNotNull(did, "State must contain 'id'");

        DidDocument document = objectMapper.convertValue(state, DidDocument.class);
        assertNotNull(document, "Failed to convert state to DidDocument");
        assertEquals(did, document.id(), "Document ID must match DID");

        DidRegistrationRequest request = new DidRegistrationRequest(did, document, List.of(logEntry));
        DidRegistrationResponse response = didService.registerDid(didJsonl);

        assertNotNull(response);
        assertTrue(response.success(), "Registration should succeed");
        assertEquals(did, response.did(), "Response DID should match");

        WebVhDidDocument resolved = didService.resolveDid(did);
        assertNotNull(resolved, "Resolved state should not be null");
        assertEquals(did, resolved.getId(), "Resolved state ID should match");
    }

    @Test
    void testResolveDid() {
        assertThrows(DidService.DidNotFoundException.class, () -> {
            didService.resolveDid("did:webvh:nonexistent:example.com");
        });
    }
}
