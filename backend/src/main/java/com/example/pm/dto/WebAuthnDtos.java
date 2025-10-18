package com.example.pm.dto;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public class WebAuthnDtos {

    public record RegistrationOptionsResponse(String requestId, JsonNode publicKey) {
    }

    public record RegistrationFinishRequest(@NotBlank String requestId, JsonNode credential) {
    }

    public record LoginOptionsRequest(@Email String email, String captchaToken) {
    }

    public record LoginOptionsResponse(String requestId, JsonNode publicKey) {
    }

    public record LoginFinishRequest(@NotBlank String requestId, JsonNode credential) {
    }
}