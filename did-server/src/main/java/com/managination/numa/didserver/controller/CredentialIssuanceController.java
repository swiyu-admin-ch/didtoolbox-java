package com.managination.numa.didserver.controller;

import com.managination.numa.didserver.dto.*;
import com.managination.numa.didserver.service.CredentialOfferStore;
import com.managination.numa.didserver.service.DidService;
import com.managination.numa.didserver.service.VCIssuanceService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping
@Tag(name = "Credential Issuance", description = "OIDC4VCI token and credential endpoints for credential issuance")
public class CredentialIssuanceController {

    private record TokenStoreEntry(
        String accessToken,
        String holderDid,
        String credentialType,
        long expiresAt
    ) {}

    private final CredentialOfferStore credentialOfferStore;
    private final VCIssuanceService vcIssuanceService;
    private final DidService didService;
    private final ConcurrentHashMap<String, TokenStoreEntry> tokenStore = new ConcurrentHashMap<>();

    public CredentialIssuanceController(CredentialOfferStore credentialOfferStore, VCIssuanceService vcIssuanceService, DidService didService) {
        this.credentialOfferStore = credentialOfferStore;
        this.vcIssuanceService = vcIssuanceService;
        this.didService = didService;
    }

    @Scheduled(fixedRate = 300000)
    public void cleanupExpiredTokens() {
        long now = System.currentTimeMillis();
        tokenStore.entrySet().removeIf(entry -> now >= entry.getValue().expiresAt());
        credentialOfferStore.cleanupExpired();
    }

    @PostMapping(value = "/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @Operation(summary = "Exchange pre-authorized code for access token (OIDC4VCI)", operationId = "requestToken")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Token issued successfully",
            content = @Content(schema = @Schema(implementation = TokenResponse.class))),
        @ApiResponse(responseCode = "400", description = "Invalid token request",
            content = @Content(schema = @Schema(implementation = OAuthErrorResponse.class))),
        @ApiResponse(responseCode = "401", description = "Invalid pre-authorized code or PIN",
            content = @Content(schema = @Schema(implementation = OAuthErrorResponse.class)))
    })
    public ResponseEntity<?> requestToken(
            @RequestParam("grant_type") String grantType,
            @RequestParam(value = "pre-authorized_code", required = false) String preAuthorizedCode,
            @RequestParam(value = "user_pin", required = false) String userPin) {
        if (!"urn:ietf:params:oauth:grant-type:pre-authorized_code".equals(grantType)) {
            return ResponseEntity.badRequest().body(new OAuthErrorResponse("unsupported_grant_type", "Only pre-authorized code grant type is supported"));
        }

        if (preAuthorizedCode == null || preAuthorizedCode.isBlank()) {
            return ResponseEntity.badRequest().body(new OAuthErrorResponse("invalid_request", "pre-authorized_code is required"));
        }

        try {
            CredentialOfferStore.CredentialOffer offer = credentialOfferStore.validateAndConsume(preAuthorizedCode, userPin);

            String accessToken = UUID.randomUUID().toString();
            long expiresAt = System.currentTimeMillis() + 3600000;
            String cNonce = UUID.randomUUID().toString();
            long cNonceExpiresAt = System.currentTimeMillis() + 3600000;

            tokenStore.put(accessToken, new TokenStoreEntry(accessToken, offer.holderDid(), offer.credentialType(), expiresAt));

            TokenResponse response = new TokenResponse(accessToken, "Bearer", 3600, cNonce, 3600, null);
            return ResponseEntity.ok(response);
        } catch (CredentialOfferStore.InvalidPreAuthorizedCodeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new OAuthErrorResponse("invalid_grant", e.getMessage()));
        } catch (CredentialOfferStore.ExpiredPreAuthorizedCodeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new OAuthErrorResponse("invalid_grant", e.getMessage()));
        } catch (CredentialOfferStore.AlreadyConsumedException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new OAuthErrorResponse("invalid_grant", e.getMessage()));
        } catch (CredentialOfferStore.InvalidPinException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new OAuthErrorResponse("invalid_grant", e.getMessage()));
        }
    }

    @PostMapping("/credential")
    @Operation(summary = "Request a verifiable credential (OIDC4VCI)", operationId = "requestCredential")
    @SecurityRequirement(name = "BearerAuth")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Credential issued successfully",
            content = @Content(schema = @Schema(implementation = CredentialResponse.class))),
        @ApiResponse(responseCode = "400", description = "Invalid credential request",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
        @ApiResponse(responseCode = "401", description = "Invalid or expired access token",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    public ResponseEntity<?> requestCredential(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @RequestBody CredentialRequest request) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ErrorResponse("unauthorized", "Bearer token is required"));
        }

        String token = authorization.substring(7);
        TokenStoreEntry entry = tokenStore.get(token);

        if (entry == null || System.currentTimeMillis() >= entry.expiresAt()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ErrorResponse("invalid_token", "Token is invalid or expired"));
        }

        if (request.format() == null) {
            return ResponseEntity.badRequest().body(new ErrorResponse("invalid_request", "format is required"));
        }

        String credentialJwt = vcIssuanceService.createCredential(entry.holderDid(), entry.credentialType(), "didService.getIssuerDid()");

        return ResponseEntity.ok(new CredentialResponse(credentialJwt, request.format()));
    }
}
