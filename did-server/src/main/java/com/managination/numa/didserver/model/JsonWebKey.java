package com.managination.numa.didserver.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public record JsonWebKey(
    String kty,
    String kid,
    String crv,
    String x,
    String y
) {}
