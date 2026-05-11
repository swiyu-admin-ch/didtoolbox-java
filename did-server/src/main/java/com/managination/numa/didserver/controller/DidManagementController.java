package com.managination.numa.didserver.controller;

import com.managination.numa.didserver.dto.*;
import com.managination.numa.didserver.model.DidDocument;
import com.managination.numa.didserver.service.DidService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

@RestController
@RequestMapping("/")
@Tag(name = "DID Management", description = "Endpoints for creating, registering, updating, and retrieving DID documents")
public class DidManagementController {

   private final DidService didService;

   public DidManagementController(DidService didService) {
      this.didService = didService;
   }

   @PostMapping
   @Operation(summary = "Register a new DID with the server", operationId = "registerDid")
   @ApiResponses(value = {
         @ApiResponse(responseCode = "200", description = "DID registered successfully",
               content = @Content(schema = @Schema(implementation = DidRegistrationResponse.class))),
         @ApiResponse(responseCode = "400", description = "Invalid DID registration request",
               content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
         @ApiResponse(responseCode = "409", description = "DID already exists with different state",
               content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
   })
   public ResponseEntity<?> registerDid(@RequestBody String didJsonl) {
      try {
         DidRegistrationResponse response = didService.verifyAndSaveDid(didJsonl);
         return ResponseEntity.ok(response);
      } catch (IllegalArgumentException e) {
         return ResponseEntity.badRequest().body(new ErrorResponse("invalid_request", e.getMessage()));
      } catch (IllegalStateException e) {
         return ResponseEntity.status(HttpStatus.CONFLICT).body(new ErrorResponse("conflict", e.getMessage()));
      } catch (Exception e) {
         return ResponseEntity.badRequest().body(new ErrorResponse("registration_failed", e.getMessage()));
      }
   }

   @GetMapping({"", "/{did}"})
   @Operation(summary = "Resolve a DID to its state", operationId = "resolveDid")
   @ApiResponses(value = {
         @ApiResponse(responseCode = "200", description = "DID state found",
               content = @Content(schema = @Schema(implementation = DidDocument.class))),
         @ApiResponse(responseCode = "404", description = "DID not found",
               content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
   })
   public ResponseEntity<?> resolveDid(
         @Parameter(description = "URL-encoded DID string", required = true)
         @PathVariable String did, HttpServletRequest request) {
      try {
         String domain = request.getServerName();
         String decodedDid = did == null || did.isBlank()
               ? ""
               : URLDecoder.decode(did, StandardCharsets.UTF_8);

         String didString = decodedDid.isBlank()
               ? domain
               : domain + ":" + decodedDid;

         return ResponseEntity.ok(didService.resolveDid("did:webvh:fakescid:" + didString));
      } catch (DidService.DidNotFoundException e) {
         return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ErrorResponse("not_found", e.getMessage()));
      } catch (IllegalArgumentException e) {
         return ResponseEntity.badRequest().body(new ErrorResponse("invalid_did", e.getMessage()));
      } catch (IOException e) {
         throw new RuntimeException(e);
      }
   }

   @PutMapping("")
   @Operation(summary = "Update an existing DID state", operationId = "updateDid")
   @ApiResponses(value = {
         @ApiResponse(responseCode = "200", description = "DID state updated successfully",
               content = @Content(schema = @Schema(implementation = DidUpdateResponse.class))),
         @ApiResponse(responseCode = "400", description = "Invalid update request",
               content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
         @ApiResponse(responseCode = "403", description = "Unauthorized - proof verification failed",
               content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
         @ApiResponse(responseCode = "409", description = "Version conflict - server has newer version",
               content = @Content(schema = @Schema(implementation = VersionConflictResponse.class)))
   })
   public ResponseEntity<?> updateDid(
         @Parameter(description = "URL-encoded DID string", required = true)
         @RequestBody String didJsonl) {
      try {
         DidRegistrationResponse response = didService.verifyAndSaveDid(didJsonl);
         return ResponseEntity.ok(response);
      } catch (DidService.DidNotFoundException e) {
         return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ErrorResponse("not_found", e.getMessage()));
      } catch (DidService.VersionConflictException e) {
         VersionConflictResponse conflict = new VersionConflictResponse(
               "version_conflict",
               e.getMessage(),
               e.getServerVersionId(),
               e.getClientVersionId(),
               e.getServerDocument()
         );
         return ResponseEntity.status(HttpStatus.CONFLICT).body(conflict);
      } catch (IllegalArgumentException e) {
         return ResponseEntity.badRequest().body(new ErrorResponse("invalid_request", e.getMessage()));
      } catch (Exception e) {
         return ResponseEntity.badRequest().body(new ErrorResponse("update_failed", e.getMessage()));
      }
   }
}
