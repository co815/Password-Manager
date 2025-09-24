package com.example.pm.auth;

import com.example.pm.config.AuthCookieProps;
import com.example.pm.repo.UserRepository;
import com.example.pm.security.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
class AuthControllerValidationTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserRepository users;

    @MockBean
    private JwtService jwtService;

    @MockBean
    private AuthCookieProps authCookieProps;

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