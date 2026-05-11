package com.managination.numa.didserver.dto;

import lombok.Getter;
import lombok.Setter;

import java.time.Instant;
import java.util.List;

/**
 * Implementation of https://raw.githubusercontent.com/decentralized-identity/didwebvh/refs/heads/main/schemas/v1.0/log_entry.json
 */
@Setter
@Getter
public class WebVhLogEntry {

    private String versionId;
    private Instant versionTime;
    private WebVhDidParameters parameters;
    private WebVhDidDocument state;
    private List<WebVhDataIntegrityProof> proof;

}
