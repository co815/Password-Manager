package com.example.pm.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document("vault_items")
public class VaultItem {
    @Id
    private String id;

    @Indexed
    private String userId;

    private String titleCipher;
    private String titleNonce;

    private String usernameCipher;
    private String usernameNonce;

    private String passwordCipher;
    private String passwordNonce;

    private String url;

    private String notesCipher;
    private String notesNonce;

    @CreatedDate
    private Instant createdAt;

    @LastModifiedDate
    private Instant updatedAt;
}