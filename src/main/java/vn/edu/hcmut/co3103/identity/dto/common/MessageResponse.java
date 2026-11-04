package vn.edu.hcmut.co3103.identity.dto.common;

import com.fasterxml.jackson.annotation.JsonProperty;

public record MessageResponse(@JsonProperty("message") String message) {
}
