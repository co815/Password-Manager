package com.example.pm.dto;
import com.example.pm.model.User;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.data.annotation.Id;

public class AuthDtos {

    public record PublicUser(
            String id,
            String email,
            String username,
            String saltClient,
            String dekEncrypted,
            String dekNonce
    ) {
        public static PublicUser fromUser(User user) {
            return new PublicUser(
                    user.getId(),
                    user.getEmail(),
                    user.getUsername(),
                    user.getSaltClient(),
                    user.getDekEncrypted(),
                    user.getDekNonce()
            );
        }
    }

    public record RegisterRequest(
            @Email String email,
            @NotBlank @Size(min = 4, max = 64) String username,
            @NotBlank String verifier,
            @NotBlank String saltClient,
            @NotBlank String dekEncrypted,
            @NotBlank String dekNonce
    ) {}

    public record RegisterResponse(
            @Id String id
    ) {}

    public record LoginRequest(
            @Email String email,
            @NotBlank String verifier
    ) {}

    public record LoginResponse(
            PublicUser user
    ) {}

    public record SaltResponse(
            String saltClient
    ) {}

}
