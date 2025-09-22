package com.example.pm.model;

import com.example.pm.dto.AuthDtos;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;
import java.util.Locale;

@Data @Builder @AllArgsConstructor @NoArgsConstructor
@Document("users")
public class User {
    @Id private String id;

    @Indexed(unique = true) @NotBlank @Email
    private String email;
    @Indexed(unique = true) @NotBlank @Size(min = 4)
    private String username;

    private String verifier;
    private String saltClient;
    private String dekEncrypted;
    private String dekNonce;
    @CreatedDate
    private Instant createdAt;

    public static User fromRegisterRequest(AuthDtos.RegisterRequest req) {
        String normalizedEmail = req.email() != null ? req.email().trim().toLowerCase(Locale.ROOT) : null;
        String normalizedUsername = req.username() != null ? req.username().trim() : null;

        return User.builder()
                .email(normalizedEmail)
                .username(normalizedUsername)
                .verifier(req.verifier())
                .saltClient(req.saltClient())
                .dekEncrypted(req.dekEncrypted())
                .dekNonce(req.dekNonce())
                .createdAt(Instant.now())
                .build();
    }
}
