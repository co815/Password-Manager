package com.example.pm.webauthn.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document("webauthnCredentials")
public class WebAuthnCredential {

    @Id
    private String id;

    @Indexed
    private String userId;

    @Indexed(unique = true)
    private String credentialId;

    private String publicKeyCose;

    private long signCount;

    private Boolean backupEligible;

    private Boolean backedUp;

    private Boolean discoverable;

    private List<String> transports;

    private String attestationType;

    private String aaguid;

    @CreatedDate
    private Instant createdAt;

    private Instant lastUsedAt;
}
