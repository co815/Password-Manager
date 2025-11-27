package com.example.pm.auth;

import com.example.pm.auditlog.SecurityAuditService;
import com.example.pm.dto.AuthDtos.LoginRequest;
import com.example.pm.dto.AuthDtos.ResendVerificationRequest;
import com.example.pm.dto.AuthDtos.SaltResponse;
import com.example.pm.dto.AuthDtos.SimpleMessageResponse;
import com.example.pm.exceptions.ErrorResponse;
import com.example.pm.model.User;
import com.example.pm.repo.UserRepository;
import com.example.pm.security.AuthSessionService;
import com.example.pm.security.CaptchaValidationService;
import com.example.pm.security.PasswordVerifier;
import com.example.pm.security.RateLimiterService;
import com.example.pm.security.TotpService;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DefaultCsrfToken;

import java.time.Duration;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class AuthControllerTest {

    @Test
    void loginSetsSecureHttpOnlyCookieWithSameSite() {
        UserRepository users = mock(UserRepository.class);
        RateLimiterService rateLimiter = mock(RateLimiterService.class);
        TotpService totp = mock(TotpService.class);
        SecurityAuditService audit = mock(SecurityAuditService.class);
        CsrfTokenRepository csrfTokenRepository = mock(CsrfTokenRepository.class);
        AuthSessionService authSessionService = mock(AuthSessionService.class);

        User user = new User();
        user.setId("user-123");
        user.setEmail("user@example.com");
        user.setUsername("john");
        user.setVerifier("verifier");
        user.setSaltClient("salt");
        user.setDekEncrypted("dek");
        user.setDekNonce("nonce");
        user.setEmailVerified(true);

        when(users.findByEmail("user@example.com")).thenReturn(Optional.of(user));

        when(rateLimiter.isAllowed(anyString())).thenReturn(true);

        PlaceholderSaltService placeholderSaltService = new PlaceholderSaltService("test-secret");
        EmailVerificationService emailVerificationService = mock(EmailVerificationService.class);
        CsrfToken csrfToken = new DefaultCsrfToken("X-XSRF-TOKEN", "_csrf", "csrf-token-value");
        ResponseCookie cookie = ResponseCookie.from("accessToken", "token-value")
                .httpOnly(true)
                .secure(true)
                .sameSite("None")
                .maxAge(Duration.ofMinutes(15))
                .build();
        when(authSessionService.startSession(eq(user), any(), any()))
                .thenReturn(new AuthSessionService.Session("token-value", cookie, csrfToken));

        AuthController controller = createController(users, rateLimiter, totp, audit, csrfTokenRepository,
                placeholderSaltService, emailVerificationService, authSessionService, null);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setSecure(true);
        request.addHeader("Origin", "https://app.example.com");
        MockHttpServletResponse responseServlet = new MockHttpServletResponse();

        ResponseEntity<?> response = controller.login(new LoginRequest("user@example.com", "verifier", null, null, null), request, responseServlet);

        String setCookie = response.getHeaders().getFirst(HttpHeaders.SET_COOKIE);
        assertThat(setCookie)
                .isNotNull()
                .contains("accessToken=token-value")
                .contains("Max-Age=900")
                .contains("SameSite=None")
                .contains("Secure")
                .contains("HttpOnly");
        assertThat(response.getHeaders().getFirst("X-XSRF-TOKEN"))
                .isEqualTo("csrf-token-value");
        verify(authSessionService).startSession(user, request, responseServlet);
    }

    @Test
    void loginSucceedsWhenVerifierMatchesAfterTrimmingWhitespace() {
        UserRepository users = mock(UserRepository.class);
        RateLimiterService rateLimiter = mock(RateLimiterService.class);
        TotpService totp = mock(TotpService.class);
        SecurityAuditService audit = mock(SecurityAuditService.class);
        CsrfTokenRepository csrfTokenRepository = mock(CsrfTokenRepository.class);
        AuthSessionService authSessionService = mock(AuthSessionService.class);

        User user = new User();
        user.setId("user-123");
        user.setEmail("user@example.com");
        user.setUsername("john");
        user.setVerifier("  verifier  ");
        user.setSaltClient("salt");
        user.setDekEncrypted("dek");
        user.setDekNonce("nonce");
        user.setEmailVerified(true);

        when(users.findByEmail("user@example.com")).thenReturn(Optional.of(user));

        when(rateLimiter.isAllowed(anyString())).thenReturn(true);

        PlaceholderSaltService placeholderSaltService = new PlaceholderSaltService("test-secret");
        EmailVerificationService emailVerificationService = mock(EmailVerificationService.class);
        CsrfToken csrfToken = new DefaultCsrfToken("X-XSRF-TOKEN", "_csrf", "csrf-token-value");
        ResponseCookie cookie = ResponseCookie.from("accessToken", "token-value")
                .httpOnly(true)
                .secure(true)
                .sameSite("Lax")
                .maxAge(Duration.ofMinutes(15))
                .build();
        when(authSessionService.startSession(eq(user), any(), any()))
                .thenReturn(new AuthSessionService.Session("token-value", cookie, csrfToken));

        AuthController controller = createController(users, rateLimiter, totp, audit, csrfTokenRepository,
                placeholderSaltService, emailVerificationService, authSessionService, null);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setSecure(true);
        MockHttpServletResponse responseServlet = new MockHttpServletResponse();

        ResponseEntity<?> response = controller.login(new LoginRequest("user@example.com", "verifier   ", null, null, null), request,
                responseServlet);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getHeaders().getFirst("X-XSRF-TOKEN")).isEqualTo("csrf-token-value");
    }

    @Test
    void loginFailsWhenVerifierDoesNotMatchAfterTrimmingWhitespace() {
        UserRepository users = mock(UserRepository.class);
        RateLimiterService rateLimiter = mock(RateLimiterService.class);
        TotpService totp = mock(TotpService.class);
        SecurityAuditService audit = mock(SecurityAuditService.class);
        CsrfTokenRepository csrfTokenRepository = mock(CsrfTokenRepository.class);
        AuthSessionService authSessionService = mock(AuthSessionService.class);

        User user = new User();
        user.setId("user-123");
        user.setEmail("user@example.com");
        user.setUsername("john");
        user.setVerifier("verifier");
        user.setSaltClient("salt");
        user.setDekEncrypted("dek");
        user.setDekNonce("nonce");
        user.setEmailVerified(true);

        when(users.findByEmail("user@example.com")).thenReturn(Optional.of(user));

        when(rateLimiter.isAllowed(anyString())).thenReturn(true);

        PlaceholderSaltService placeholderSaltService = new PlaceholderSaltService("test-secret");
        EmailVerificationService emailVerificationService = mock(EmailVerificationService.class);

        PasswordVerifier passwordVerifier = mock(PasswordVerifier.class);
        when(passwordVerifier.verify(any(), any())).thenReturn(false);

        AuthController controller = createController(users, rateLimiter, totp, audit, csrfTokenRepository,
                placeholderSaltService, emailVerificationService, authSessionService, passwordVerifier);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setSecure(true);

        ResponseEntity<?> response = controller.login(new LoginRequest("user@example.com", "   wrong   ", null, null, null), request,
                new MockHttpServletResponse());

        assertThat(response.getStatusCode().value()).isEqualTo(401);
        assertThat(response.getBody()).isInstanceOf(ErrorResponse.class);
        ErrorResponse error = (ErrorResponse) response.getBody();
        assertThat(error.error()).isEqualTo("UNAUTHORIZED");
        verify(audit).recordLoginFailure("user@example.com");
        verify(authSessionService, never()).startSession(any(), any(), any());
    }

    @Test
    void loginFailsWhenEmailNotVerified() {
        UserRepository users = mock(UserRepository.class);
        RateLimiterService rateLimiter = mock(RateLimiterService.class);
        TotpService totp = mock(TotpService.class);
        SecurityAuditService audit = mock(SecurityAuditService.class);
        CsrfTokenRepository csrfTokenRepository = mock(CsrfTokenRepository.class);
        AuthSessionService authSessionService = mock(AuthSessionService.class);

        User user = new User();
        user.setId("user-123");
        user.setEmail("user@example.com");
        user.setUsername("john");
        user.setVerifier("verifier");
        user.setSaltClient("salt");
        user.setDekEncrypted("dek");
        user.setDekNonce("nonce");
        user.setEmailVerified(false);

        when(users.findByEmail("user@example.com")).thenReturn(Optional.of(user));

        when(rateLimiter.isAllowed(anyString())).thenReturn(true);

        PlaceholderSaltService placeholderSaltService = new PlaceholderSaltService("test-secret");
        EmailVerificationService emailVerificationService = mock(EmailVerificationService.class);
        AuthController controller = createController(users, rateLimiter, totp, audit, csrfTokenRepository,
                placeholderSaltService, emailVerificationService, authSessionService, null);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setSecure(true);

        ResponseEntity<?> response = controller.login(new LoginRequest("user@example.com", "verifier", null, null, null), request,
                new MockHttpServletResponse());

        assertThat(response.getStatusCode().value()).isEqualTo(403);
        assertThat(response.getBody()).isInstanceOf(ErrorResponse.class);
        ErrorResponse error = (ErrorResponse) response.getBody();
        assertThat(error.error()).isEqualTo("EMAIL_NOT_VERIFIED");
        verify(audit).recordLoginFailure("user@example.com");
        verify(authSessionService, never()).startSession(any(), any(), any());
    }

    @Test
    void verifyEmailReturnsOkWhenTokenValid() {
        UserRepository users = mock(UserRepository.class);
        RateLimiterService rateLimiter = mock(RateLimiterService.class);
        TotpService totp = mock(TotpService.class);
        SecurityAuditService audit = mock(SecurityAuditService.class);
        CsrfTokenRepository csrfTokenRepository = mock(CsrfTokenRepository.class);
        EmailVerificationService emailVerificationService = mock(EmailVerificationService.class);
        AuthSessionService authSessionService = mock(AuthSessionService.class);

        when(emailVerificationService.verifyToken("token"))
                .thenReturn(EmailVerificationService.VerificationResult.VERIFIED);

        PlaceholderSaltService placeholderSaltService = new PlaceholderSaltService("test-secret");
        AuthController controller = createController(
                users,
                rateLimiter,
                totp,
                audit,
                csrfTokenRepository,
                placeholderSaltService,
                emailVerificationService,
                authSessionService,
                null);

        ResponseEntity<?> response = controller.verifyEmail("token");

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).isInstanceOf(SimpleMessageResponse.class);
    }

    @Test
    void verifyEmailReturnsGoneWhenExpired() {
        UserRepository users = mock(UserRepository.class);
        RateLimiterService rateLimiter = mock(RateLimiterService.class);
        TotpService totp = mock(TotpService.class);
        SecurityAuditService audit = mock(SecurityAuditService.class);
        CsrfTokenRepository csrfTokenRepository = mock(CsrfTokenRepository.class);
        EmailVerificationService emailVerificationService = mock(EmailVerificationService.class);
        AuthSessionService authSessionService = mock(AuthSessionService.class);

        when(emailVerificationService.verifyToken("token"))
                .thenReturn(EmailVerificationService.VerificationResult.EXPIRED);

        PlaceholderSaltService placeholderSaltService = new PlaceholderSaltService("test-secret");
        AuthController controller = createController(
                users,
                rateLimiter,
                totp,
                audit,
                csrfTokenRepository,
                placeholderSaltService,
                emailVerificationService,
                authSessionService,
                null);

        ResponseEntity<?> response = controller.verifyEmail("token");

        assertThat(response.getStatusCode().value()).isEqualTo(410);
        assertThat(response.getBody()).isInstanceOf(ErrorResponse.class);
    }

    @Test
    void resendVerificationReturnsAccepted() {
        UserRepository users = mock(UserRepository.class);
        RateLimiterService rateLimiter = mock(RateLimiterService.class);
        TotpService totp = mock(TotpService.class);
        SecurityAuditService audit = mock(SecurityAuditService.class);
        CsrfTokenRepository csrfTokenRepository = mock(CsrfTokenRepository.class);
        EmailVerificationService emailVerificationService = mock(EmailVerificationService.class);
        AuthSessionService authSessionService = mock(AuthSessionService.class);

        when(emailVerificationService.resendVerification("user@example.com"))
                .thenReturn(EmailVerificationService.ResendResult.SENT);

        PlaceholderSaltService placeholderSaltService = new PlaceholderSaltService("test-secret");
        AuthController controller = createController(
                users,
                rateLimiter,
                totp,
                audit,
                csrfTokenRepository,
                placeholderSaltService,
                emailVerificationService,
                authSessionService,
                null);

        ResponseEntity<?> response = controller.resendVerification(new ResendVerificationRequest("user@example.com"));

        assertThat(response.getStatusCode().value()).isEqualTo(202);
        assertThat(response.getBody()).isInstanceOf(SimpleMessageResponse.class);
    }

    @Test
    void resendVerificationReturnsConflictWhenAlreadyVerified() {
        UserRepository users = mock(UserRepository.class);
        RateLimiterService rateLimiter = mock(RateLimiterService.class);
        TotpService totp = mock(TotpService.class);
        SecurityAuditService audit = mock(SecurityAuditService.class);
        CsrfTokenRepository csrfTokenRepository = mock(CsrfTokenRepository.class);
        EmailVerificationService emailVerificationService = mock(EmailVerificationService.class);
        AuthSessionService authSessionService = mock(AuthSessionService.class);

        when(emailVerificationService.resendVerification("user@example.com"))
                .thenReturn(EmailVerificationService.ResendResult.ALREADY_VERIFIED);

        PlaceholderSaltService placeholderSaltService = new PlaceholderSaltService("test-secret");
        AuthController controller = createController(
                users,
                rateLimiter,
                totp,
                audit,
                csrfTokenRepository,
                placeholderSaltService,
                emailVerificationService,
                authSessionService,
                null);

        ResponseEntity<?> response = controller.resendVerification(new ResendVerificationRequest("user@example.com"));

        assertThat(response.getStatusCode().value()).isEqualTo(409);
        assertThat(response.getBody()).isInstanceOf(ErrorResponse.class);
    }

    @Test
    void loginKeepsSecureCookieEvenWhenOriginIsHttp() {
        UserRepository users = mock(UserRepository.class);
        RateLimiterService rateLimiter = mock(RateLimiterService.class);
        TotpService totp = mock(TotpService.class);
        SecurityAuditService audit = mock(SecurityAuditService.class);
        CsrfTokenRepository csrfTokenRepository = mock(CsrfTokenRepository.class);
        AuthSessionService authSessionService = mock(AuthSessionService.class);

        User user = new User();
        user.setId("user-123");
        user.setEmail("user@example.com");
        user.setUsername("john");
        user.setVerifier("verifier");
        user.setSaltClient("salt");
        user.setDekEncrypted("dek");
        user.setDekNonce("nonce");
        user.setEmailVerified(true);

        when(users.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(rateLimiter.isAllowed(anyString())).thenReturn(true);

        PlaceholderSaltService placeholderSaltService = new PlaceholderSaltService("test-secret");
        EmailVerificationService emailVerificationService = mock(EmailVerificationService.class);
        CsrfToken csrfToken = new DefaultCsrfToken("X-XSRF-TOKEN", "_csrf", "csrf-token-value");
        ResponseCookie cookie = ResponseCookie.from("accessToken", "token-value")
                .httpOnly(true)
                .secure(true)
                .sameSite("None")
                .maxAge(Duration.ofMinutes(15))
                .build();
        when(authSessionService.startSession(eq(user), any(), any()))
                .thenReturn(new AuthSessionService.Session("token-value", cookie, csrfToken));

        AuthController controller = createController(users, rateLimiter, totp, audit, csrfTokenRepository,
                placeholderSaltService, emailVerificationService, authSessionService, null);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setSecure(true);
        request.addHeader("Origin", "http://localhost:5173");
        MockHttpServletResponse responseServlet = new MockHttpServletResponse();

        ResponseEntity<?> response = controller.login(new LoginRequest("user@example.com", "verifier", null, null, null), request, responseServlet);

        String setCookie = response.getHeaders().getFirst(HttpHeaders.SET_COOKIE);
        assertThat(setCookie)
                .isNotNull()
                .contains("accessToken=token-value")
                .contains("Max-Age=900")
                .contains("SameSite=None")
                .contains("Secure")
                .contains("HttpOnly");
        assertThat(response.getHeaders().getFirst("X-XSRF-TOKEN")).isEqualTo("csrf-token-value");
    }

    @Test
    void loginKeepsSecureCookieWithSameSiteNoneWhenForwardedProtoIsHttp() {
        UserRepository users = mock(UserRepository.class);
        RateLimiterService rateLimiter = mock(RateLimiterService.class);
        TotpService totp = mock(TotpService.class);
        SecurityAuditService audit = mock(SecurityAuditService.class);
        CsrfTokenRepository csrfTokenRepository = mock(CsrfTokenRepository.class);
        AuthSessionService authSessionService = mock(AuthSessionService.class);

        User user = new User();
        user.setId("user-123");
        user.setEmail("user@example.com");
        user.setUsername("john");
        user.setVerifier("verifier");
        user.setSaltClient("salt");
        user.setDekEncrypted("dek");
        user.setDekNonce("nonce");
        user.setEmailVerified(true);

        when(users.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(rateLimiter.isAllowed(anyString())).thenReturn(true);

        PlaceholderSaltService placeholderSaltService = new PlaceholderSaltService("test-secret");
        EmailVerificationService emailVerificationService = mock(EmailVerificationService.class);
        CsrfToken csrfToken = new DefaultCsrfToken("X-XSRF-TOKEN", "_csrf", "csrf-token-value");
        ResponseCookie cookie = ResponseCookie.from("accessToken", "token-value")
                .httpOnly(true)
                .secure(true)
                .sameSite("None")
                .maxAge(Duration.ofMinutes(15))
                .build();
        when(authSessionService.startSession(eq(user), any(), any()))
                .thenReturn(new AuthSessionService.Session("token-value", cookie, csrfToken));

        AuthController controller = createController(users, rateLimiter, totp, audit, csrfTokenRepository,
                placeholderSaltService, emailVerificationService, authSessionService, null);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setSecure(true);
        request.addHeader("X-Forwarded-Proto", "http");
        MockHttpServletResponse responseServlet = new MockHttpServletResponse();

        ResponseEntity<?> response = controller.login(new LoginRequest("user@example.com", "verifier", null, null, null), request, responseServlet);

        String setCookie = response.getHeaders().getFirst(HttpHeaders.SET_COOKIE);
        assertThat(setCookie)
                .isNotNull()
                .contains("accessToken=token-value")
                .contains("Max-Age=900")
                .contains("SameSite=None")
                .contains("Secure")
                .contains("HttpOnly");
        assertThat(response.getHeaders().getFirst("X-XSRF-TOKEN"))
                .isEqualTo("csrf-token-value");
    }

    @Test
    void loginReturnsTooManyRequestsWhenRateLimitExceeded() {
        UserRepository users = mock(UserRepository.class);
        RateLimiterService rateLimiter = mock(RateLimiterService.class);
        TotpService totp = mock(TotpService.class);
        SecurityAuditService audit = mock(SecurityAuditService.class);
        CsrfTokenRepository csrfTokenRepository = mock(CsrfTokenRepository.class);
        AuthSessionService authSessionService = mock(AuthSessionService.class);

        when(rateLimiter.isAllowed(anyString())).thenReturn(false);
        PlaceholderSaltService placeholderSaltService = new PlaceholderSaltService("test-secret");
        EmailVerificationService emailVerificationService = mock(EmailVerificationService.class);
        AuthController controller = createController(
                users,
                rateLimiter,
                totp,
                audit,
                csrfTokenRepository,
                placeholderSaltService,
                emailVerificationService,
                authSessionService,
                null);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setSecure(true);

        ResponseEntity<?> response = controller.login(
                new LoginRequest("user@example.com", "verifier", null, null, null),
                request,
                new MockHttpServletResponse()
        );

        assertThat(response.getStatusCode().value()).isEqualTo(429);
        assertThat(response.getBody()).isInstanceOf(ErrorResponse.class);
        ErrorResponse error = (ErrorResponse) response.getBody();
        assertThat(error.error()).isEqualTo("TOO_MANY_REQUESTS");
    }


    @Test
    void saltReturnsStoredSaltForKnownEmail() {
        UserRepository users = mock(UserRepository.class);
        RateLimiterService rateLimiter = mock(RateLimiterService.class);
        TotpService totp = mock(TotpService.class);
        SecurityAuditService audit = mock(SecurityAuditService.class);
        CsrfTokenRepository csrfTokenRepository = mock(CsrfTokenRepository.class);
        AuthSessionService authSessionService = mock(AuthSessionService.class);
        CsrfToken csrfToken = new DefaultCsrfToken("X-XSRF-TOKEN", "_csrf", "csrf-token-value");
        when(csrfTokenRepository.generateToken(any())).thenReturn(csrfToken);

        User user = new User();
        user.setEmail("user@example.com");
        user.setSaltClient("stored-salt");

        when(users.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(rateLimiter.isAllowed(anyString())).thenReturn(true);

        PlaceholderSaltService placeholderSaltService = new PlaceholderSaltService("test-secret");
        EmailVerificationService emailVerificationService = mock(EmailVerificationService.class);
        AuthController controller = createController(
                users,
                rateLimiter,
                totp,
                audit,
                csrfTokenRepository,
                placeholderSaltService,
                emailVerificationService,
                authSessionService,
                null);

        MockHttpServletRequest request = new MockHttpServletRequest();

        ResponseEntity<?> response = controller.salt("User@Example.com", request);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).isInstanceOf(SaltResponse.class);
        SaltResponse salt = (SaltResponse) response.getBody();
        assertThat(salt.email()).isEqualTo("user@example.com");
        assertThat(salt.saltClient()).isEqualTo("stored-salt");
    }

    @Test
    void saltHidesWhetherUsernameExists() {
        UserRepository users = mock(UserRepository.class);
        RateLimiterService rateLimiter = mock(RateLimiterService.class);
        TotpService totp = mock(TotpService.class);
        SecurityAuditService audit = mock(SecurityAuditService.class);
        CsrfTokenRepository csrfTokenRepository = mock(CsrfTokenRepository.class);
        AuthSessionService authSessionService = mock(AuthSessionService.class);
        CsrfToken csrfToken = new DefaultCsrfToken("X-XSRF-TOKEN", "_csrf", "csrf-token-value");
        when(csrfTokenRepository.generateToken(any())).thenReturn(csrfToken);

        when(users.findByUsername("unknown_user"))
                .thenReturn(Optional.empty());
        when(rateLimiter.isAllowed(anyString())).thenReturn(true);

        PlaceholderSaltService placeholderSaltService = new PlaceholderSaltService("test-secret");
        EmailVerificationService emailVerificationService = mock(EmailVerificationService.class);
        AuthController controller = createController(
                users,
                rateLimiter,
                totp,
                audit,
                csrfTokenRepository,
                placeholderSaltService,
                emailVerificationService,
                authSessionService,
                null);

        MockHttpServletRequest request = new MockHttpServletRequest();

        ResponseEntity<?> response = controller.salt("Unknown_User!!!", request);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).isInstanceOf(SaltResponse.class);
        SaltResponse salt = (SaltResponse) response.getBody();
        assertThat(salt.email()).isEqualTo("unknown_user@example.invalid");
        assertThat(salt.saltClient()).isNotBlank();
    }

    @Test
    void saltReturnsStableFakeValueForUnknownEmail() {
        UserRepository users = mock(UserRepository.class);
        RateLimiterService rateLimiter = mock(RateLimiterService.class);
        TotpService totp = mock(TotpService.class);
        SecurityAuditService audit = mock(SecurityAuditService.class);
        CsrfTokenRepository csrfTokenRepository = mock(CsrfTokenRepository.class);
        AuthSessionService authSessionService = mock(AuthSessionService.class);
        CsrfToken csrfToken = new DefaultCsrfToken("X-XSRF-TOKEN", "_csrf", "csrf-token-value");
        when(csrfTokenRepository.generateToken(any())).thenReturn(csrfToken);

        when(users.findByEmail("ghost@example.com")).thenReturn(Optional.empty());
        when(rateLimiter.isAllowed(anyString())).thenReturn(true);

        PlaceholderSaltService placeholderSaltService = new PlaceholderSaltService("test-secret");
        EmailVerificationService emailVerificationService = mock(EmailVerificationService.class);
        AuthController controller = createController(
                users,
                rateLimiter,
                totp,
                audit,
                csrfTokenRepository,
                placeholderSaltService,
                emailVerificationService,
                authSessionService,
                null);

        MockHttpServletRequest request = new MockHttpServletRequest();

        ResponseEntity<?> firstResponse = controller.salt("ghost@example.com", request);
        ResponseEntity<?> secondResponse = controller.salt("ghost@example.com", request);

        assertThat(firstResponse.getBody()).isInstanceOf(SaltResponse.class);
        assertThat(secondResponse.getBody()).isInstanceOf(SaltResponse.class);
        SaltResponse first = (SaltResponse) firstResponse.getBody();
        SaltResponse second = (SaltResponse) secondResponse.getBody();

        assertThat(first.email()).isEqualTo("ghost@example.com");
        assertThat(second.email()).isEqualTo("ghost@example.com");
        assertThat(first.saltClient()).isNotBlank();
        assertThat(second.saltClient()).isNotBlank();
        assertThat(first.saltClient()).isEqualTo(second.saltClient());
    }

    private AuthController createController(UserRepository users,
                                            RateLimiterService rateLimiter,
                                            TotpService totp,
                                            SecurityAuditService audit,
                                            CsrfTokenRepository csrfTokenRepository,
                                            PlaceholderSaltService placeholderSaltService,
                                            EmailVerificationService emailVerificationService,
                                            AuthSessionService authSessionService,
                                            PasswordVerifier passwordVerifier) {
        CaptchaValidationService captchaValidationService = mock(CaptchaValidationService.class);
        when(captchaValidationService.validateCaptcha(any(), any())).thenReturn(true);
        if (passwordVerifier == null) {
            passwordVerifier = mock(PasswordVerifier.class);
            when(passwordVerifier.verify(any(), any())).thenReturn(true);
        }
        return new AuthController(users, rateLimiter, totp, audit, captchaValidationService,
                placeholderSaltService, emailVerificationService, authSessionService, csrfTokenRepository, passwordVerifier);
    }
}
