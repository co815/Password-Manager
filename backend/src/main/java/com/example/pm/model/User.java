package com.example.pm.model;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

@Data @Builder @AllArgsConstructor @NoArgsConstructor
@Document("users")
public class User {
    @Id private String id;

    @Indexed(unique = true)     // ensures the email is unique
    @NotBlank                   // Ensures the email is not empty
    @Email                      // ensures the string is a well-formed address
    private String email;

    private String verifier;            // hashed password from frontend
    private String saltClient;          // client-generated salt
    private String dekEncrypted;        // encrypted data encryption key
    private String dekNonce;            // nonce for DEK

    @CreatedDate                // sets the creation data automatically (needs the "@EnableMongoAuditing" from MongoConfig.java class)
    private Instant createdAt;        // the date when the object was created
}
