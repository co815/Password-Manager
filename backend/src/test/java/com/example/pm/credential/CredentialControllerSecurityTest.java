package com.example.pm.credential;

import com.example.pm.TestSupportConfig;
import com.example.pm.auditlog.AuditLogAspect;
import com.example.pm.auditlog.AuditLogController;
import com.example.pm.auth.EmailVerificationService;
import com.example.pm.auth.PlaceholderSaltService;
import com.example.pm.config.TestMongoConfig;
import com.example.pm.dto.CredentialDtos;
import com.example.pm.model.Credential;
import com.example.pm.model.User;
import com.example.pm.repo.AuditLogRepository;
import com.example.pm.repo.CredentialRepository;
import com.example.pm.repo.UserRepository;
import com.example.pm.repo.VaultItemRepository;
import com.example.pm.security.AuthSessionService;
import com.example.pm.security.JwtService;
import com.example.pm.webauthn.MongoWebAuthnCredentialRepository;
import com.example.pm.webauthn.WebAuthnCredentialRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.mapping.MongoMappingContext;

import java.util.List;
import java.util.Optional;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ActiveProfiles("test")
@SpringBootTest(properties = {
        "app.jwt.secret=test_secret_key_with_more_than_32_chars!!",
        "app.jwt.expiryMinutes=15",
        "server.ssl.enabled=false",
        "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.mongo.MongoAutoConfiguration,org.springframework.boot.autoconfigure.data.mongo.MongoDataAutoConfiguration,org.springframework.boot.autoconfigure.data.mongo.MongoRepositoriesAutoConfiguration",
        "spring.data.mongodb.repositories.enabled=false"
})
@AutoConfigureMockMvc
@Import({TestMongoConfig.class, TestSupportConfig.class})
class CredentialControllerSecurityTest {

    @Autowired MockMvc mockMvc;
    @Autowired JwtService jwtService;
    @Autowired ObjectMapper objectMapper;

    @MockBean(name = "mongoTemplate") private MongoTemplate mongoTemplate;
    @MockBean(name = "mongoMappingContext") private MongoMappingContext mongoMappingContext;

    @MockBean UserRepository userRepository;
    @MockBean CredentialRepository credentialRepository;
    @MockBean VaultItemRepository vaultItemRepository;
    @MockBean AuditLogRepository auditLogRepository;
    @MockBean AuditLogController auditLogController;
    @MockBean AuditLogAspect auditLogAspect;
    @MockBean PlaceholderSaltService placeholderSaltService;
    @MockBean EmailVerificationService emailVerificationService;
    @MockBean AuthSessionService authSessionService;
    @MockBean MongoWebAuthnCredentialRepository mongoWebAuthnCredentialRepository;
    @MockBean WebAuthnCredentialRepository webAuthnCredentialRepository;

    @Test
    void listCredentialsWithoutTokenReturns401() throws Exception {
        mockMvc.perform(get("/api/credentials").secure(true))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void listCredentialsWithTokenReturnsItems() throws Exception {
        Credential c = new Credential();
        c.setId("cred-1");
        c.setUserId("user-123");
        c.setService("Email");
        c.setWebsiteLink("https://mail.example");
        c.setUsernameEncrypted("uEnc");
        c.setUsernameNonce("uNonce");
        c.setPasswordEncrypted("pEnc");
        c.setPasswordNonce("pNonce");

        when(credentialRepository.findByUserId("user-123")).thenReturn(List.of(c));
        stubUser("user-123");

        String token = jwtService.generate("user-123", 0);

        mockMvc.perform(get("/api/credentials")
                        .secure(true)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credentials[0].credentialId").value("cred-1"))
                .andExpect(jsonPath("$.credentials[0].service").value("Email"));
    }

    @Test
    void createCredentialWithoutTokenReturns401() throws Exception {
        var req = new CredentialDtos.AddCredentialRequest(
                "Email", "https://mail.example", "uEnc", "uNonce", "pEnc", "pNonce", false
        );

        mockMvc.perform(post("/api/credentials")
                        .secure(true)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void createCredentialWithoutCsrfTokenReturns403() throws Exception {
        stubUser("user-123");
        String token = jwtService.generate("user-123", 0);

        var req = new CredentialDtos.AddCredentialRequest(
                "Email", "https://mail.example", "uEnc", "uNonce", "pEnc", "pNonce", false
        );

        mockMvc.perform(post("/api/credentials")
                        .secure(true)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isForbidden());
    }

    @Test
    void createCredentialDuplicateServiceReturns409() throws Exception {
        stubUser("user-123");
        String token = jwtService.generate("user-123", 0);
        when(credentialRepository.findByUserIdAndServiceIgnoreCase("user-123", "Email"))
                .thenReturn(Optional.of(new Credential()));

        var req = new CredentialDtos.AddCredentialRequest(
                "Email", "https://mail.example", "uEnc", "uNonce", "pEnc", "pNonce", false
        );

        mockMvc.perform(post("/api/credentials")
                        .secure(true)
                        .with(csrf())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value("CONFLICT"))
                .andExpect(jsonPath("$.message", containsString("already exist")));
    }

    private void stubUser(String userId) {
        User user = new User();
        user.setId(userId);
        user.setTokenVersion(0);
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
    }
}
