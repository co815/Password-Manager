package com.example.pm.security;

import com.example.pm.TestSupportConfig;
import com.example.pm.auditlog.AuditLogAspect;
import com.example.pm.auditlog.AuditLogController;
import com.example.pm.auth.EmailVerificationService;
import com.example.pm.auth.PlaceholderSaltService;
import com.example.pm.config.TestMongoConfig;
import com.example.pm.repo.AuditLogRepository;
import com.example.pm.repo.CredentialRepository;
import com.example.pm.repo.UserRepository;
import com.example.pm.repo.VaultItemRepository;
import com.example.pm.security.AuthSessionService;
import com.example.pm.webauthn.MongoWebAuthnCredentialRepository;
import com.example.pm.webauthn.WebAuthnCredentialRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.mapping.MongoMappingContext;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ActiveProfiles("test")
@SpringBootTest(properties = {
        "app.jwt.secret=test_secret_key_with_more_than_32_chars!!",
        "server.ssl.enabled=false",
        "app.cors.origins[0]=http://localhost:5173",
        "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.mongo.MongoAutoConfiguration,org.springframework.boot.autoconfigure.data.mongo.MongoDataAutoConfiguration",
        "spring.data.mongodb.repositories.enabled=false"
})
@AutoConfigureMockMvc
@Import({TestMongoConfig.class, TestSupportConfig.class})
class CorsIntegrationTest {

    @Autowired MockMvc mockMvc;

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
    void preflightFromDisallowedOriginIsForbidden() throws Exception {
        mockMvc.perform(options("/api/auth/csrf")
                        .secure(true)
                        .header(HttpHeaders.ORIGIN, "http://evil.example")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET"))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
    }

    @Test
    void allowedOriginReceivesAllowOriginHeader() throws Exception {
        String origin = "http://localhost:5173";
        mockMvc.perform(options("/api/auth/csrf")
                        .secure(true)
                        .header(HttpHeaders.ORIGIN, origin))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, origin));
    }
}
