package com.example.pm.dto;

import com.example.pm.model.Credential;
import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

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

    public record GetAllCredentialResponse(
            List<PublicCredential> credentials
    ) {}

    public record AddCredentialRequest(
            @JsonProperty("service")
            @JsonAlias("title")
            @NotBlank
            String service,

            @JsonProperty("websiteLink")
            @JsonAlias("url")
            String websiteLink,

            @JsonProperty("usernameEncrypted")
            @JsonAlias("usernameCipher")
            @NotBlank
            String usernameEncrypted,

            @JsonProperty("usernameNonce")
            @NotBlank
            String usernameNonce,

            @JsonProperty("passwordEncrypted")
            @JsonAlias("passwordCipher")
            @NotBlank
            String passwordEncrypted,

            @JsonProperty("passwordNonce")
            @NotBlank
            String passwordNonce
    ) {}

    public record UpdateCredentialRequest(
            String service,
            String websiteLink,
            String usernameEncrypted,
            String usernameNonce,
            String passwordEncrypted,
            String passwordNonce
    ) {}

}
