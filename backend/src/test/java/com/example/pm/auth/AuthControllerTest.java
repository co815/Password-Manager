package com.example.pm.auth;

import com.example.pm.config.AuthCookieProps;
import com.example.pm.dto.AuthDtos.LoginRequest;
import com.example.pm.model.User;
import com.example.pm.repo.UserRepository;
import com.example.pm.security.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;

import java.time.Duration;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthControllerTest {

    @Test
    void loginSetsSecureSameSiteCookie() {
        UserRepository users = mock(UserRepository.class);
        JwtService jwt = mock(JwtService.class);
        AuthCookieProps props = new AuthCookieProps();
        props.setSameSite(AuthCookieProps.SameSiteMode.NONE);

        User user = new User();
        user.setId("user-1");
        user.setEmail("user@example.com");
        user.setUsername("user-name");
        user.setVerifier("verifier");
        user.setSaltClient("salt");
        user.setDekEncrypted("dek");
        user.setDekNonce("nonce");

        when(users.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(jwt.generate("user-1")).thenReturn("token-value");
        when(jwt.getExpiry()).thenReturn(Duration.ofMinutes(15));

        AuthController controller = new AuthController(users, jwt, props, true);
        ResponseEntity<?> response = controller.login(new LoginRequest("user@example.com", "verifier"));

        String setCookie = response.getHeaders().getFirst(HttpHeaders.SET_COOKIE);
        assertThat(setCookie)
                .contains("accessToken=token-value")
                .contains("Max-Age=900")
                .contains("SameSite=None")
                .contains("Secure")
                .contains("HttpOnly");
    }
}
