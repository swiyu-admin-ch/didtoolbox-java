package com.managination.numa.didserver.dto;

import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

@Setter
@Getter
public class WebVhDataIntegrityProof {

    private String id;
    private String type = "DataIntegrityProof";
    private String cryptosuite = "eddsa-jcs-2022";
    private String proofPurpose = "assertionMethod";
    private String proofValue;
    private String verificationMethod;
    private Instant created;
    private Instant expires;

}
