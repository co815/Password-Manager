package com.example.pm.security;

import com.example.pm.auditlog.AuditLogAspect;
import com.example.pm.auditlog.AuditLogController;
import com.example.pm.repo.CredentialRepository;
import com.example.pm.repo.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.mongo.MongoAutoConfiguration,org.springframework.boot.autoconfigure.data.mongo.MongoDataAutoConfiguration",
        "server.ssl.enabled=false",
        "app.jwt.secret=test_secret_key_with_more_than_32_chars!!"
})
@AutoConfigureMockMvc
class CorsIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserRepository userRepository;

    @MockBean
    private CredentialRepository credentialRepository;

    @MockBean
    private AuditLogController auditLogController;

    @MockBean
    private AuditLogAspect auditLogAspect;

    @MockBean
    private AuditLogRepository auditLogRepository;

    @Test
    void disallowedOriginDoesNotReceiveAllowOriginHeader() throws Exception {
        mockMvc.perform(get("/api/health")
                        .secure(true)
                        .header(HttpHeaders.ORIGIN, "https://evil.example"))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
    }

    @Test
    void allowedOriginReceivesAllowOriginHeader() throws Exception {
        String origin = "http://localhost:5173";
        mockMvc.perform(get("/api/health")
                        .secure(true)
                        .header(HttpHeaders.ORIGIN, origin))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, origin));
    }
}