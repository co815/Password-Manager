package com.example.pm.auth;

import com.example.pm.config.AuthCookieProps;
import com.example.pm.dto.AuthDtos.LoginRequest;
import com.example.pm.dto.AuthDtos.SaltResponse;
import com.example.pm.model.User;
import com.example.pm.repo.UserRepository;
import com.example.pm.security.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;

import java.time.Duration;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class AuthControllerTest {

    @Test
    void loginSetsSecureHttpOnlyCookieWithSameSite() {
        UserRepository users = mock(UserRepository.class);
        JwtService jwt = mock(JwtService.class);

        User user = new User();
        user.setId("user-123");
        user.setEmail("user@example.com");
        user.setUsername("john");
        user.setVerifier("verifier");
        user.setSaltClient("salt");
        user.setDekEncrypted("dek");
        user.setDekNonce("nonce");

        when(users.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(jwt.generate("user-123")).thenReturn("token-value");
        when(jwt.getExpiry()).thenReturn(Duration.ofMinutes(15));

        AuthCookieProps props = new AuthCookieProps();
        props.setSameSite("None");

        AuthController controller = new AuthController(users, jwt, props, true);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setSecure(true);
        request.addHeader("Origin", "https://app.example.com");

        ResponseEntity<?> response = controller.login(new LoginRequest("user@example.com", "verifier"), request);

        String setCookie = response.getHeaders().getFirst(HttpHeaders.SET_COOKIE);
        assertThat(setCookie)
                .isNotNull()
                .contains("accessToken=token-value")
                .contains("Max-Age=900")
                .contains("SameSite=None")
                .contains("Secure")
                .contains("HttpOnly");
    }

    @Test
    void loginKeepsSecureCookieEvenWhenOriginIsHttp() {
        UserRepository users = mock(UserRepository.class);
        JwtService jwt = mock(JwtService.class);

        User user = new User();
        user.setId("user-123");
        user.setEmail("user@example.com");
        user.setUsername("john");
        user.setVerifier("verifier");
        user.setSaltClient("salt");
        user.setDekEncrypted("dek");
        user.setDekNonce("nonce");

        when(users.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(jwt.generate("user-123")).thenReturn("token-value");
        when(jwt.getExpiry()).thenReturn(Duration.ofMinutes(15));

        AuthCookieProps props = new AuthCookieProps();
        props.setSameSite("None");

        AuthController controller = new AuthController(users, jwt, props, true);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setSecure(true);
        request.addHeader("Origin", "http://localhost:5173");

        ResponseEntity<?> response = controller.login(new LoginRequest("user@example.com", "verifier"), request);

        String setCookie = response.getHeaders().getFirst(HttpHeaders.SET_COOKIE);
        assertThat(setCookie)
                .isNotNull()
                .contains("accessToken=token-value")
                .contains("Max-Age=900")
                .contains("SameSite=None")
                .contains("Secure")
                .contains("HttpOnly");
    }

    @Test
    void loginDowngradesToNonSecureCookieWhenForwardedProtoIsHttp() {
        UserRepository users = mock(UserRepository.class);
        JwtService jwt = mock(JwtService.class);

        User user = new User();
        user.setId("user-123");
        user.setEmail("user@example.com");
        user.setUsername("john");
        user.setVerifier("verifier");
        user.setSaltClient("salt");
        user.setDekEncrypted("dek");
        user.setDekNonce("nonce");

        when(users.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(jwt.generate("user-123")).thenReturn("token-value");
        when(jwt.getExpiry()).thenReturn(Duration.ofMinutes(15));

        AuthCookieProps props = new AuthCookieProps();
        props.setSameSite("None");

        AuthController controller = new AuthController(users, jwt, props, true);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setSecure(true);
        request.addHeader("X-Forwarded-Proto", "http");

        ResponseEntity<?> response = controller.login(new LoginRequest("user@example.com", "verifier"), request);

        String setCookie = response.getHeaders().getFirst(HttpHeaders.SET_COOKIE);
        assertThat(setCookie)
                .isNotNull()
                .contains("accessToken=token-value")
                .contains("Max-Age=900")
                .contains("SameSite=Lax")
                .doesNotContain("SameSite=None")
                .doesNotContain("Secure")
                .contains("HttpOnly");
    }

    @Test
    void saltReturnsStoredSaltForKnownEmail() {
        UserRepository users = mock(UserRepository.class);
        JwtService jwt = mock(JwtService.class);

        User user = new User();
        user.setEmail("user@example.com");
        user.setSaltClient("stored-salt");

        when(users.findByEmail("user@example.com")).thenReturn(Optional.of(user));

        AuthCookieProps props = new AuthCookieProps();
        AuthController controller = new AuthController(users, jwt, props, true);

        ResponseEntity<?> response = controller.salt("User@Example.com");

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).isInstanceOf(SaltResponse.class);
        SaltResponse salt = (SaltResponse) response.getBody();
        assertThat(salt.email()).isEqualTo("user@example.com");
        assertThat(salt.saltClient()).isEqualTo("stored-salt");
    }

    @Test
    void saltHidesWhetherUsernameExists() {
        UserRepository users = mock(UserRepository.class);
        JwtService jwt = mock(JwtService.class);

        when(users.findByUsername("unknown_user"))
                .thenReturn(Optional.empty());

        AuthCookieProps props = new AuthCookieProps();
        AuthController controller = new AuthController(users, jwt, props, true);

        ResponseEntity<?> response = controller.salt("Unknown_User!!!");

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).isInstanceOf(SaltResponse.class);
        SaltResponse salt = (SaltResponse) response.getBody();
        assertThat(salt.email()).isEqualTo("unknown_user@example.invalid");
        assertThat(salt.saltClient()).isNotBlank();
    }

    @Test
    void saltReturnsDifferentFakeValuesForUnknownEmail() {
        UserRepository users = mock(UserRepository.class);
        JwtService jwt = mock(JwtService.class);

        when(users.findByEmail("ghost@example.com")).thenReturn(Optional.empty());

        AuthCookieProps props = new AuthCookieProps();
        AuthController controller = new AuthController(users, jwt, props, true);

        ResponseEntity<?> firstResponse = controller.salt("ghost@example.com");
        ResponseEntity<?> secondResponse = controller.salt("ghost@example.com");

        assertThat(firstResponse.getBody()).isInstanceOf(SaltResponse.class);
        assertThat(secondResponse.getBody()).isInstanceOf(SaltResponse.class);
        SaltResponse first = (SaltResponse) firstResponse.getBody();
        SaltResponse second = (SaltResponse) secondResponse.getBody();

        assertThat(first.email()).isEqualTo("ghost@example.com");
        assertThat(second.email()).isEqualTo("ghost@example.com");
        assertThat(first.saltClient()).isNotBlank();
        assertThat(second.saltClient()).isNotBlank();
        assertThat(first.saltClient()).isNotEqualTo(second.saltClient());
    }
}
