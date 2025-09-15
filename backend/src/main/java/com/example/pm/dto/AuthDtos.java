package com.example.pm.dto;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public class AuthDtos {

    public record RegisterRequest(
            @Email String email,
            @NotBlank String verifier,
            @NotBlank String saltClient,
            @NotBlank String dekEncrypted,
            @NotBlank String dekNonce
    ) {}

    public record LoginRequest(@Email String email, @NotBlank String verifier) {}

    public record PublicUser(String id, String email, String saltClient, String dekEncrypted, String dekNonce) {}

    public record LoginResponse(String accessToken, PublicUser user) {}
}
