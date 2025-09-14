package com.example.pm.model;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

@Data @Builder @AllArgsConstructor @NoArgsConstructor
@Document("users")
public class User {
    @Id private String id;
    @Indexed(unique = true) private String email;
    private String verifier;
    private String saltClient;
    private String dekEncrypted;
    private String dekNonce;
    private Instant createdAt;
}
