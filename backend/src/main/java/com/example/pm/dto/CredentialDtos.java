package com.example.pm.dto;

import com.example.pm.model.Credential;

import java.util.List;

public class CredentialDtos {

    public record PublicCredential(
            String credentialId,
            String service,
            String websiteLink,

            String usernameEncrypted,
            String usernameNonce,

            String passwordEncrypted,
            String passwordNonce
    ) {
        public static PublicCredential fromCredential(Credential credential){
            return new PublicCredential(
                    credential.getId(),
                    credential.getService(),
                    credential.getWebsiteLink(),
                    credential.getUsernameEncrypted(),
                    credential.getUsernameNonce(),
                    credential.getPasswordEncrypted(),
                    credential.getPasswordNonce()
            );
        }
    }

    // Get credential
    public record GetAllCredentialResponse(
            List<PublicCredential> credentials
    ) {}

    // Add new credential
    public record AddCredentialRequest(
            String service,
            String websiteLink,
            String usernameEncrypted,
            String usernameNonce,
            String passwordEncrypted,
            String passwordNonce
    ) {}

    // Update a credential
    public record UpdateCredentialRequest(
            String service,
            String websiteLink,
            String usernameEncrypted,
            String usernameNonce,
            String passwordEncrypted,
            String passwordNonce
    ) {}

}
