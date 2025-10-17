package com.example.pm.model;

import com.example.pm.dto.CredentialDtos;
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

    private String usernameEncrypted;        // username/email
    private String usernameNonce;

    private String passwordEncrypted;   // password Encrypted
    private String passwordNonce;       //
    private boolean favorite;

    @CreatedDate private Instant createdAt;

    public static Credential fromPostRequest(CredentialDtos.AddCredentialRequest addRequest){
        return Credential.builder()
                .service(addRequest.service())
                .websiteLink(addRequest.websiteLink())
                .usernameEncrypted(addRequest.usernameEncrypted())
                .usernameNonce(addRequest.usernameNonce())
                .passwordEncrypted(addRequest.passwordEncrypted())
                .passwordNonce(addRequest.passwordNonce())
                .favorite(Boolean.TRUE.equals(addRequest.favorite()))
                .build();
    }

}
