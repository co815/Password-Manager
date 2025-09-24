package com.example.pm.vault;

import com.example.pm.auditlog.AuditLogAspect;
import com.example.pm.auditlog.AuditLogController;
import com.example.pm.config.TestMongoConfig;
import com.example.pm.model.VaultItem;
import com.example.pm.repo.AuditLogRepository;
import com.example.pm.repo.CredentialRepository;
import com.example.pm.repo.UserRepository;
import com.example.pm.repo.VaultItemRepository;
import com.example.pm.security.JwtService;
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

import java.time.Instant;
import java.util.List;

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
        "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.mongo.MongoAutoConfiguration,org.springframework.boot.autoconfigure.data.mongo.MongoDataAutoConfiguration",
        "spring.data.mongodb.repositories.enabled=false"
})
@AutoConfigureMockMvc
@Import(TestMongoConfig.class)
class VaultControllerSecurityTest {

    @Autowired MockMvc mockMvc;
    @Autowired JwtService jwtService;
    @Autowired ObjectMapper objectMapper;

    @MockBean(name = "mongoTemplate") private MongoTemplate mongoTemplate;
    @MockBean(name = "mongoMappingContext") private MongoMappingContext mongoMappingContext;

    @MockBean UserRepository userRepository;
    @MockBean VaultItemRepository vaultItemRepository;
    @MockBean CredentialRepository credentialRepository;
    @MockBean AuditLogRepository auditLogRepository;
    @MockBean AuditLogController auditLogController;
    @MockBean AuditLogAspect auditLogAspect;

    @Test
    void listVaultWithoutTokenReturns401() throws Exception {
        mockMvc.perform(get("/api/vault").secure(true))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void listVaultWithTokenReturnsItems() throws Exception {
        VaultItem item = new VaultItem();
        item.setId("item-1");
        item.setUserId("user-123");
        item.setTitleCipher("titleCipher");
        item.setTitleNonce("titleNonce");
        item.setUsernameCipher("usernameCipher");
        item.setUsernameNonce("usernameNonce");
        item.setPasswordCipher("passwordCipher");
        item.setPasswordNonce("passwordNonce");
        item.setUrl("https://example.com");
        item.setCreatedAt(Instant.now());

        when(vaultItemRepository.findByUserId("user-123")).thenReturn(List.of(item));
        String token = jwtService.generate("user-123");

        mockMvc.perform(get("/api/vault")
                        .secure(true)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value("item-1"))
                .andExpect(jsonPath("$[0].usernameCipher").value("usernameCipher"));
    }

    @Test
    void createVaultWithoutTokenReturns401() throws Exception {
        String payload = """
                {
                  "titleCipher":"tC","titleNonce":"tN",
                  "usernameCipher":"uC","usernameNonce":"uN",
                  "passwordCipher":"pC","passwordNonce":"pN",
                  "url":"https://example.com"
                }
                """;

        mockMvc.perform(post("/api/vault")
                        .secure(true)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isUnauthorized());
    }
}
