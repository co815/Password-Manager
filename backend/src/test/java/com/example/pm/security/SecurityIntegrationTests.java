package com.example.pm.security;

import com.example.pm.TestSupportConfig;
import com.example.pm.model.AuditLog;
import com.example.pm.model.User;
import com.example.pm.model.VaultItem;
import com.example.pm.repo.AuditLogRepository;
import com.example.pm.repo.CredentialRepository;
import com.example.pm.repo.UserRepository;
import com.example.pm.repo.VaultItemRepository;
import com.example.pm.security.RateLimiterService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import jakarta.servlet.http.HttpServletRequest;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.mockito.Mockito.lenient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "security.salt.rate-limit.requests=2",
        "security.salt.rate-limit.window-seconds=3600"
})
@Import(TestSupportConfig.class)
class SecurityIntegrationTests {

    private static final String VALID_VAULT_PAYLOAD = """
            {
              \"titleCipher\":\"t\",\"titleNonce\":\"tn\",\"usernameCipher\":\"u\",
              \"usernameNonce\":\"un\",\"passwordCipher\":\"p\",\"passwordNonce\":\"pn\"
            }
            """;

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private VaultItemRepository vaultItemRepository;

    @MockBean
    private UserRepository userRepository;

    @MockBean
    private AuditLogRepository auditLogRepository;

    @MockBean
    private CredentialRepository credentialRepository;

    @MockBean
    private RateLimiterService rateLimiterService;

    @BeforeEach
    void setUpMocks() {
        reset(vaultItemRepository, auditLogRepository, userRepository, credentialRepository, rateLimiterService);
        lenient().when(vaultItemRepository.save(any(VaultItem.class)))
                .thenAnswer(invocation -> {
                    VaultItem item = invocation.getArgument(0);
                    if (item.getId() == null) {
                        item.setId("vault-1");
                    }
                    if (item.getCreatedAt() == null) {
                        item.setCreatedAt(Instant.now());
                    }
                    if (item.getUpdatedAt() == null) {
                        item.setUpdatedAt(Instant.now());
                    }
                    return item;
                });
        lenient().when(auditLogRepository.save(any(AuditLog.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
    }

    @Test
    void csrfTokenIsProvidedInCookieAndHeader() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/health"))
                .andExpect(status().isOk())
                .andExpect(header().exists("X-CSRF-TOKEN"))
                .andReturn();

        String csrfToken = result.getResponse().getHeader("X-CSRF-TOKEN");
        assertThat(csrfToken).isNotBlank();

        List<String> setCookieHeaders = result.getResponse().getHeaders("Set-Cookie");
        assertThat(setCookieHeaders).isNotEmpty();
        String xsrfCookieHeader = setCookieHeaders.stream()
                .filter(headerValue -> headerValue.startsWith("XSRF-TOKEN="))
                .findFirst()
                .orElseThrow();

        assertThat(xsrfCookieHeader).doesNotContain("HttpOnly");
        assertThat(xsrfCookieHeader).contains("SameSite=Strict");
    }

    @Test
    void requestWithoutCsrfHeaderIsRejected() throws Exception {
        String token = obtainCsrfToken();
        Cookie csrfCookie = buildCsrfCookie(token);

        mockMvc.perform(post("/api/vault")
                        .cookie(csrfCookie)
                        .with(authentication(authenticatedUser()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(VALID_VAULT_PAYLOAD))
                .andExpect(status().isForbidden());
    }

    @Test
    void requestWithCsrfHeaderIsAccepted() throws Exception {
        String token = obtainCsrfToken();
        Cookie csrfCookie = buildCsrfCookie(token);

        mockMvc.perform(post("/api/vault")
                        .cookie(csrfCookie)
                        .with(authentication(authenticatedUser()))
                        .with(user("tester").roles("USER"))
                        .header("X-CSRF-TOKEN", token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(VALID_VAULT_PAYLOAD))
                .andExpect(status().isOk());
    }

    @Test
    void saltEndpointIsRateLimited() throws Exception {
        when(userRepository.findByEmail("known@example.com"))
                .thenReturn(Optional.of(User.builder()
                        .id("user-1")
                        .email("known@example.com")
                        .username("known")
                        .saltClient("real-salt")
                        .build()));

        when(rateLimiterService.isAllowed(anyString())).thenReturn(true, false);

        mockMvc.perform(get("/api/auth/salt").param("identifier", "known@example.com"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/auth/salt").param("identifier", "known@example.com"))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.error").value("TOO_MANY_REQUESTS"));
    }

    private String obtainCsrfToken() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/health"))
                .andExpect(status().isOk())
                .andReturn();
        return result.getResponse().getHeader("X-CSRF-TOKEN");
    }

    private Cookie buildCsrfCookie(String token) {
        Cookie cookie = new Cookie("XSRF-TOKEN", token);
        cookie.setHttpOnly(false);
        cookie.setPath("/");
        return cookie;
    }

    private UsernamePasswordAuthenticationToken authenticatedUser() {
        return new UsernamePasswordAuthenticationToken("user-1", null, List.of());
    }
}
