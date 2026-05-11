package com.managination.numa.didserver.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
@Setter
@Getter
public class WebVhWitness {

    private Integer threshold;
    private List<Map<String, Object>> witnesses;

}
