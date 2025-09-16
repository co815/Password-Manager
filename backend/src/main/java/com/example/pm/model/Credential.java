package com.example.pm.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Document("credentials")
public class Credential {
    @Id private String id;
    private String userId;
    private String service;         // facebook, gmail, etc.
    private String websiteLink;     // www.facebook.com
    private String username;        // username/email
    private String passwordEncrypted;   // password Encrypted
    private String passwordNonce;       //
    @CreatedDate private Instant createdAt;
}
