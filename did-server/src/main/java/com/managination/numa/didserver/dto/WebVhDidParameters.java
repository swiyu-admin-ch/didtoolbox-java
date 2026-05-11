package com.managination.numa.didserver.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
@Setter
@Getter
public class WebVhDidParameters {

    private String method = "did:webvh:1.0";
    private String scid;
    private Boolean portable;
    private List<String> updateKeys;
    private List<String> nextKeyHashes;
    private List<String> watchers;
    private WebVhWitness witness;
    private Boolean deactivated;
    private Integer ttl;

}
