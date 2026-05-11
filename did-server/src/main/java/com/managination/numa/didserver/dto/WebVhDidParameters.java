package com.managination.numa.didserver.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Setter
@Getter
public class WebVhDidParameters {

    private String method = "did:webvh:";
    private String scid;
    private Boolean portable;
    private List<String> updateKeys;
    private List<String> nextKeyHashes;
    private List<String> watchers;
    private WebVhWitness witness;
    private Boolean deactivated;
    private Integer ttl;

}
