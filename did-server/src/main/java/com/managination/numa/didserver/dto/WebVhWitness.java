package com.managination.numa.didserver.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Map;

@Setter
@Getter
public class WebVhWitness {

    private Integer threshold;
    private List<Map<String, Object>> witnesses;

}
