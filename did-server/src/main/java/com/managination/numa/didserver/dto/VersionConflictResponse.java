package com.managination.numa.didserver.dto;

import com.managination.numa.didserver.model.DidDocument;

public record VersionConflictResponse(
    String error,
    String message,
    String serverVersionId,
    String clientVersionId,
    WebVhDidDocument serverDocument
) {}
