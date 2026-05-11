package com.managination.numa.didserver.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
@Setter
@Getter
public class WebVhDidDocument {

    @JsonProperty("@context")
    private Object context;
    private String id;
    private List<WebVhVerificationMethod> verificationMethod;
    private List<Object> assertionMethod;
    private List<Object> authentication;
    private List<Object> capabilityInvocation;
    private List<Object> capabilityDelegation;
    private List<Object> keyAgreement;
    private List<WebVhService> service;

}
