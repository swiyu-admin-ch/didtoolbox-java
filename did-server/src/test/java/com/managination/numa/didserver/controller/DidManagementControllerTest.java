package com.managination.numa.didserver.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class DidManagementControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void testRegisterDidInvalidFormat() throws Exception {
        String body = """
            {
                "did": "invalid-did",
                "document": {"id": "invalid-did"},
                "log": []
            }
            """;

        mockMvc.perform(post("/")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
            .andExpect(status().isBadRequest());
    }

    @Test
    void testRegisterDidMissingDocument() throws Exception {
        String body = """
            {
                "did": "did:webvh:test:example.com",
                "log": []
            }
            """;

        mockMvc.perform(post("/")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
            .andExpect(status().isBadRequest());
    }

    @Test
    void testResolveDidNotFound() throws Exception {
        mockMvc.perform(get("/did%3Awebvh%3Anonexistent%3Aexample.com"))
            .andExpect(status().isNotFound());
    }

    @Test
    void testUpdateDidNotFound() throws Exception {
        String updateBody = """
            {
                "document": {"id": "did:webvh:nonexistent:example.com"},
                "versionId": "0"
            }
            """;

        mockMvc.perform(put("/")
                .contentType(MediaType.APPLICATION_JSON)
                .content(updateBody))
            .andExpect(status().isBadRequest());
    }
}
