package com.example.pm.dto;

import com.example.pm.model.Credential;

import java.util.List;

public class CredentialDtos {

    public record PublicCredential(
            String credentialId,
            String service,
            String website,
            String username,
            String passwordEncrypted,
            String passwordNonce
    ) {
        public static PublicCredential fromCredential(Credential credential){
            return new PublicCredential(
                    credential.getId(),
                    credential.getService(),
                    credential.getWebsiteLink(),
                    credential.getUsername(),
                    credential.getPasswordEncrypted(),
                    credential.getPasswordNonce()
            );
        }
    }

    // Get credential
    public record GetAllCredentialResponse(
            List<PublicCredential> credentials
    ) {}


}
