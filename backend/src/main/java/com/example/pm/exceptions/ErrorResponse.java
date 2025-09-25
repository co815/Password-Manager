package com.example.pm.exceptions;

import com.fasterxml.jackson.annotation.JsonProperty;

public record ErrorResponse(int status, @JsonProperty("error") String error, String message) {
    @JsonProperty("type")
    public String type() {
        return error;
    }
}