package com.example.pm.dto;
import com.example.pm.model.User;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import org.springframework.data.annotation.Id;

public class AuthDtos {

    // PublicUser - the user object that will interact with the frontend
    public record PublicUser(
            String id,
            String email,
            String saltClient,
            String dekEncrypted,
            String dekNonce
    ) {
        public static PublicUser fromUser(User user) {
            return new PublicUser(
                    user.getId(),
                    user.getEmail(),
                    user.getSaltClient(),
                    user.getDekEncrypted(),
                    user.getDekNonce()
            );
        }
    }

    // Register request/response
    public record RegisterRequest(
            @Email String email,
            @NotBlank String verifier,
            @NotBlank String saltClient,
            @NotBlank String dekEncrypted,
            @NotBlank String dekNonce
    ) {}

    public record RegisterResponse(
            @Id String id
    ) {}

    // Login request/response
    public record LoginRequest(
            @Email String email,
            @NotBlank String verifier
    ) {}

    public record LoginResponse(
            PublicUser user
    ) {}

    // Salt response
    public record SaltResponse(
            String saltClient
    ) {}

}
