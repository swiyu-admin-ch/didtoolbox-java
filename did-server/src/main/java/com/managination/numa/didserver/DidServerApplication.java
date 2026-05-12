package com.managination.numa.didserver;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Main entry point for the DID Server application.
 * <p>
 * This Spring Boot application provides a REST API for managing Decentralized Identifiers (DIDs)
 * using the did:webvh method. It supports uploading, verifying, and serving DID documents.
 * </p>
 *
 * @author Swiss Federal Chancellery
 */
@OpenAPIDefinition(
    info = @Info(
        title = "DID Server API",
        version = "2.0.0",
        description = """
            API for managing Decentralized Identifiers (DIDs) using the did:webvh method, \
            credential issuance sessions, verifiable presentations, and reward claiming.
            
            ## DID Format
            
            This server supports the `did:webvh` method with SCID (Self-Contained Identifier).
            
            **Format:** `did:webvh:SCID:domain[:path...]`
            
            **Example:** `did:webvh:SCID:example.com:.well-known`
            
            ## Storage Structure
            
            DID files are stored as `did.jsonl` in the following structure:
            - Root domain: `{storagePath}/{domain}/.well-known/did.jsonl`
            - Sub-path: `{storagePath}/{domain}/{path}/did.jsonl`
            
            ## WebSocket Sessions
            
            Credential issuance uses WebSocket sessions for real-time communication between issuer and holder. \
            See `did-server-asyncapi.json` for the complete WebSocket channel specification.
            """,
        contact = @Contact(name = "Swiss Federal Chancellery"),
        license = @License(name = "Apache License 2.0")
    ),
    servers = {
        @Server(url = "http://localhost:8080", description = "Local development server"),
        @Server(url = "https://did.ninja", description = "Production server")
    },
    tags = {
        @Tag(name = "DID Management", description = "Endpoints for creating, registering, updating, and retrieving DID documents"),
        @Tag(name = "Health", description = "Health check and system status endpoints"),
        @Tag(name = "Documentation", description = "API documentation endpoints"),
        @Tag(name = "Credential Issuance", description = "OIDC4VCI token and credential endpoints for credential issuance"),
        @Tag(name = "Sessions", description = "WebSocket session management for peer-to-peer credential issuance"),
        @Tag(name = "Verifiable Presentations", description = "Endpoints for submitting and verifying verifiable presentations"),
        @Tag(name = "Rewards", description = "Reward claiming and NFT issuance endpoints"),
        @Tag(name = "Server Configuration", description = "Server public key and configuration endpoints")
    }
)
@SecurityScheme(
    name = "BearerAuth",
    type = SecuritySchemeType.HTTP,
    scheme = "bearer",
    description = "OAuth 2.0 Bearer token obtained from the /token endpoint"
)
@SpringBootApplication
public class DidServerApplication {

    /**
     * Application entry point that bootstraps the Spring Boot context.
     *
     * @param args command-line arguments passed to the application
     */
    public static void main(String[] args) {
        SpringApplication.run(DidServerApplication.class, args);
    }
}

