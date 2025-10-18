package com.example.pm.credential;

import com.example.pm.TestSupportConfig;
import com.example.pm.auditlog.AuditLogAspect;
import com.example.pm.auditlog.AuditLogController;
import com.example.pm.config.TestMongoConfig;
import com.example.pm.dto.AuthDtos;
import com.example.pm.model.Credential;
import com.example.pm.model.User;
import com.example.pm.repo.AuditLogRepository;
import com.example.pm.repo.CredentialRepository;
import com.example.pm.repo.UserRepository;
import com.example.pm.repo.VaultItemRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.mapping.MongoMappingContext;

import java.net.HttpCookie;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ActiveProfiles("test")
@org.springframework.test.annotation.DirtiesContext(classMode = org.springframework.test.annotation.DirtiesContext.ClassMode.BEFORE_CLASS)
@SpringBootTest(properties = {
        "app.jwt.secret=test_secret_key_with_more_than_32_chars!!",
        "app.jwt.expiryMinutes=15",
        "server.ssl.enabled=false",
        "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.mongo.MongoAutoConfiguration,org.springframework.boot.autoconfigure.data.mongo.MongoDataAutoConfiguration,org.springframework.boot.autoconfigure.data.mongo.MongoRepositoriesAutoConfiguration",
        "spring.data.mongodb.repositories.enabled=false"
})
@AutoConfigureMockMvc
@Import({TestMongoConfig.class, TestSupportConfig.class})
class CredentialControllerIntegrationTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    ObjectMapper objectMapper;

    @MockBean(name = "mongoTemplate")
    MongoTemplate mongoTemplate;

    @MockBean(name = "mongoMappingContext")
    MongoMappingContext mongoMappingContext;

    @MockBean
    UserRepository userRepository;

    @MockBean
    CredentialRepository credentialRepository;

    @MockBean
    VaultItemRepository vaultItemRepository;

    @MockBean
    AuditLogRepository auditLogRepository;

    @MockBean
    AuditLogController auditLogController;

    @MockBean
    AuditLogAspect auditLogAspect;

    private final Map<String, User> userStore = new ConcurrentHashMap<>();
    private final Map<String, Credential> credentialStore = new ConcurrentHashMap<>();

    @BeforeEach
    void setUpMocks() {
        userStore.clear();
        credentialStore.clear();

        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0, User.class);
            if (user.getId() == null || user.getId().isBlank()) {
                user.setId(UUID.randomUUID().toString());
            }
            userStore.put(user.getId(), user);
            return user;
        });

        when(userRepository.findByEmail(anyString())).thenAnswer(invocation -> {
            String email = invocation.getArgument(0);
            if (email == null) {
                return Optional.empty();
            }
            return userStore.values().stream()
                    .filter(u -> email.equals(u.getEmail()))
                    .findFirst();
        });

        when(userRepository.findById(anyString())).thenAnswer(invocation -> {
            String id = invocation.getArgument(0);
            return Optional.ofNullable(userStore.get(id));
        });

        when(userRepository.findByUsername(anyString())).thenAnswer(invocation -> {
            String username = invocation.getArgument(0);
            if (username == null) {
                return Optional.empty();
            }
            return userStore.values().stream()
                    .filter(u -> username.equals(u.getUsername()))
                    .findFirst();
        });

        when(credentialRepository.save(any(Credential.class))).thenAnswer(invocation -> {
            Credential credential = invocation.getArgument(0, Credential.class);
            if (credential.getId() == null || credential.getId().isBlank()) {
                credential.setId(UUID.randomUUID().toString());
            }
            credentialStore.put(credential.getId(), credential);
            return credential;
        });

        when(credentialRepository.findByUserId(anyString())).thenAnswer(invocation -> {
            String userId = invocation.getArgument(0);
            return credentialStore.values().stream()
                    .filter(c -> userId != null && userId.equals(c.getUserId()))
                    .toList();
        });

        when(credentialRepository.findByUserIdAndService(anyString(), anyString())).thenAnswer(invocation -> {
            String userId = invocation.getArgument(0);
            String service = invocation.getArgument(1);
            return credentialStore.values().stream()
                    .filter(c -> userId != null && userId.equals(c.getUserId())
                            && service != null && service.equals(c.getService()))
                    .findFirst();
        });

        Mockito.doAnswer(invocation -> {
            Credential credential = invocation.getArgument(0, Credential.class);
            credentialStore.remove(credential.getId());
            return null;
        }).when(credentialRepository).delete(any(Credential.class));
    }

    @Test
    void authenticatedUserCanCreateCredentialWhenSupplyingCsrfToken() throws Exception {
        var registerRequest = new AuthDtos.RegisterRequest(
                "alice@example.com",
                "alice",
                "sampleVerifier",
                "clientSalt",
                "encryptedDek",
                "dekNonce",
                null,
                null
        );

        MvcResult registerCsrfResult = mockMvc.perform(MockMvcRequestBuilders.get("/api/auth/csrf"))
                .andExpect(status().isOk())
                .andReturn();

        Cookie registerCsrfCookie = extractCookie(registerCsrfResult, "XSRF-TOKEN");
        String registerCsrfToken = Optional.ofNullable(registerCsrfResult.getResponse().getHeader("X-XSRF-TOKEN"))
                .orElseGet(registerCsrfCookie::getValue);

        mockMvc.perform(MockMvcRequestBuilders.post("/api/auth/register")
                        .cookie(registerCsrfCookie)
                        .header("X-XSRF-TOKEN", registerCsrfToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isOk());

        userStore.values().forEach(user -> user.setEmailVerified(true));

        var loginRequest = new AuthDtos.LoginRequest(registerRequest.email(), registerRequest.verifier(), null, null, null);

        MvcResult loginCsrfResult = mockMvc.perform(MockMvcRequestBuilders.get("/api/auth/csrf"))
                .andExpect(status().isOk())
                .andReturn();

        Cookie loginCsrfCookie = extractCookie(loginCsrfResult, "XSRF-TOKEN");
        String loginCsrfToken = Optional.ofNullable(loginCsrfResult.getResponse().getHeader("X-XSRF-TOKEN"))
                .orElseGet(loginCsrfCookie::getValue);

        MvcResult loginResult = mockMvc.perform(MockMvcRequestBuilders.post("/api/auth/login")
                        .cookie(loginCsrfCookie)
                        .header("X-XSRF-TOKEN", loginCsrfToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        Cookie accessTokenCookie = extractCookie(loginResult, "accessToken");

        MvcResult credentialCsrfResult = mockMvc.perform(MockMvcRequestBuilders.get("/api/auth/csrf"))
                .andExpect(status().isOk())
                .andReturn();

        Cookie csrfCookie = extractCookie(credentialCsrfResult, "XSRF-TOKEN");
        String csrfToken = Optional.ofNullable(credentialCsrfResult.getResponse().getHeader("X-XSRF-TOKEN"))
                .orElseGet(csrfCookie::getValue);

        mockMvc.perform(MockMvcRequestBuilders.post("/api/credential")
                        .cookie(accessTokenCookie, csrfCookie)
                        .header("X-XSRF-TOKEN", csrfToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "service": "GitHub",
                                  "websiteLink": "https://github.com",
                                  "usernameEncrypted": "enc-user",
                                  "usernameNonce": "nonce-user",
                                  "passwordEncrypted": "enc-pass",
                                  "passwordNonce": "nonce-pass"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.service").value("GitHub"));

        assertThat(credentialStore.values())
                .anyMatch(cred -> "GitHub".equals(cred.getService()) && "alice@example.com".equals(resolveEmailForUser(cred.getUserId())));
    }

    private String resolveEmailForUser(String userId) {
        if (userId == null) {
            return null;
        }
        User user = userStore.get(userId);
        return user != null ? user.getEmail() : null;
    }

    private Cookie extractCookie(MvcResult result, String name) {
        List<String> setCookies = result.getResponse().getHeaders("Set-Cookie");
        for (String header : setCookies) {
            for (HttpCookie httpCookie : HttpCookie.parse(header)) {
                if (httpCookie.getName().equals(name)) {
                    Cookie servletCookie = new Cookie(httpCookie.getName(), httpCookie.getValue());
                    servletCookie.setPath(Optional.ofNullable(httpCookie.getPath()).orElse("/"));
                    return servletCookie;
                }
            }
        }
        if ("XSRF-TOKEN".equals(name)) {
            String headerToken = result.getResponse().getHeader("X-XSRF-TOKEN");
            if (headerToken != null && !headerToken.isBlank()) {
                Cookie servletCookie = new Cookie(name, headerToken);
                servletCookie.setPath("/");
                return servletCookie;
            }
        }
        throw new AssertionError("Missing cookie: " + name);
    }
}
