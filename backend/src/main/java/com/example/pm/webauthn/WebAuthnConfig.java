package com.example.pm.webauthn;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import java.util.Set;
import java.util.stream.Collectors;

@Configuration
@Profile("!test")
public class WebAuthnConfig {

    @Bean
    public RelyingParty relyingParty(WebAuthnProperties properties,
                                     MongoWebAuthnCredentialRepository credentialRepository) {
        RelyingPartyIdentity identity = RelyingPartyIdentity.builder()
                .id(properties.getRelyingPartyId())
                .name(properties.getRelyingPartyName())
                .build();

        Set<String> origins = properties.getOrigins().stream()
                .filter(origin -> origin != null && !origin.isBlank())
                .collect(Collectors.toSet());

        return RelyingParty.builder()
                .identity(identity)
                .credentialRepository(credentialRepository)
                .origins(origins)
                .build();
    }

    @Bean(name = "webauthnObjectMapper")
    public ObjectMapper webauthnObjectMapper() {
        return JsonMapper.builder().findAndAddModules().build();
    }
}