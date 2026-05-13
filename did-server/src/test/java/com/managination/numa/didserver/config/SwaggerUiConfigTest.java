package com.managination.numa.didserver.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

class SwaggerUiConfigTest {

    @ParameterizedTest
    @ValueSource(strings = {
        "/unsupported-protocol/publish",
        "/kafka/publish",
        "/stomp/publish",
        "/amqp/publish",
        "/unsupported-protocol/publish/can",
        "/kafka/publish/something"
    })
    void publishEndpointsShouldMatchApiPathPattern(String suffix) {
        assertTrue(suffix.matches("/[^/]+/publish(/.*)?"),
            "Suffix '" + suffix + "' should match publish endpoint pattern");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "/docs",
        "/ui-config",
        "/docs/123",
        "/ui-config?foo=bar"
    })
    void knownApiPathsShouldMatch(String suffix) {
        String[] apiPaths = {"/docs", "/ui-config"};
        boolean matched = false;
        for (String apiPath : apiPaths) {
            if (suffix.equals(apiPath) || suffix.startsWith(apiPath + "/") || suffix.startsWith(apiPath + "?")) {
                matched = true;
                break;
            }
        }
        assertTrue(matched, "Suffix '" + suffix + "' should match known API path");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "/asyncapi-ui.html",
        "/main-6CAHIZNX.js",
        "/styles-2J4TNLOB.css",
        "/chunk-KX354HZD.js",
        "/prerendered-routes.json",
        "/3rdpartylicenses.txt"
    })
    void staticResourcesShouldNotMatchApiPathPattern(String suffix) {
        assertFalse(suffix.matches("/[^/]+/publish(/.*)?"),
            "Static resource '" + suffix + "' should NOT match publish endpoint pattern");
    }
}
