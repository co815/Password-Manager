package com.example.pm.auth;

import com.example.pm.TestSupportConfig;
import com.example.pm.config.AuthCookieProps;
import com.example.pm.auditlog.SecurityAuditService;
import com.example.pm.repo.UserRepository;
import com.example.pm.security.JwtService;
import com.example.pm.security.TotpService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ActiveProfiles("test")
@WebMvcTest(controllers = AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import({AuthCookieProps.class, TestSupportConfig.class})
class AuthControllerValidationTest {

    @Autowired MockMvc mockMvc;

    @MockBean UserRepository userRepository;
    @MockBean JwtService jwtService;
    @MockBean TotpService totpService;
    @MockBean SecurityAuditService auditService;
    @MockBean org.springframework.security.web.csrf.CsrfTokenRepository csrfTokenRepository;
    @MockBean PlaceholderSaltService placeholderSaltService;

    @Test
    void registerMissingFieldsReturnsBadRequestWithValidationDetails() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.type").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.message", containsString("username")))
                .andExpect(jsonPath("$.message", containsString("verifier")))
                .andExpect(jsonPath("$.message", containsString("saltClient")))
                .andExpect(jsonPath("$.message", containsString("dekEncrypted")))
                .andExpect(jsonPath("$.message", containsString("dekNonce")));
    }
}
