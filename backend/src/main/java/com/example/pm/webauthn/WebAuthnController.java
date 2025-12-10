package com.example.pm.webauthn;

import com.example.pm.auditlog.SecurityAuditService;
import com.example.pm.dto.AuthDtos.LoginResponse;
import com.example.pm.dto.AuthDtos.PublicUser;
import com.example.pm.dto.AuthDtos.SimpleMessageResponse;
import com.example.pm.dto.WebAuthnDtos.LoginFinishRequest;
import com.example.pm.dto.WebAuthnDtos.LoginOptionsRequest;
import com.example.pm.dto.WebAuthnDtos.LoginOptionsResponse;
import com.example.pm.dto.WebAuthnDtos.RegistrationFinishRequest;
import com.example.pm.dto.WebAuthnDtos.RegistrationOptionsResponse;
import com.example.pm.exceptions.ErrorResponse;
import com.example.pm.model.User;
import com.example.pm.repo.UserRepository;
import com.example.pm.security.AuthSessionService;
import com.example.pm.security.CaptchaValidationService;
import com.example.pm.security.RateLimiterService;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Locale;
import java.util.Optional;

@RestController
@Profile("!test")
@RequestMapping("/api/auth/webauthn")
@SuppressWarnings("null") // Suppress Spring null-safety false positives
public class WebAuthnController {

    private final WebAuthnService webAuthnService;
    private final UserRepository userRepository;
    private final SecurityAuditService auditService;
    private final AuthSessionService authSessionService;
    private final RateLimiterService rateLimiterService;
    private final CaptchaValidationService captchaValidationService;
    private final ObjectMapper webauthnObjectMapper;

    public WebAuthnController(WebAuthnService webAuthnService,
            UserRepository userRepository,
            SecurityAuditService auditService,
            AuthSessionService authSessionService,
            RateLimiterService rateLimiterService,
            CaptchaValidationService captchaValidationService,
            @Qualifier("webauthnObjectMapper") ObjectMapper webauthnObjectMapper) {
        this.webAuthnService = webAuthnService;
        this.userRepository = userRepository;
        this.auditService = auditService;
        this.authSessionService = authSessionService;
        this.rateLimiterService = rateLimiterService;
        this.captchaValidationService = captchaValidationService;
        this.webauthnObjectMapper = webauthnObjectMapper;
    }

    @PostMapping("/register/options")
    public ResponseEntity<?> startRegistration(Authentication authentication) {
        if (authentication == null || authentication.getPrincipal() == null) {
            return ResponseEntity.status(401)
                    .body(new ErrorResponse(401, "UNAUTHORIZED", "Invalid Credentials"));
        }
        String userId = (String) authentication.getPrincipal();
        return userRepository.findById(userId)
                .<ResponseEntity<?>>map(user -> {
                    WebAuthnService.RegistrationStart start = webAuthnService.startRegistration(
                            user.getId(), user.getEmail(), user.getUsername());
                    JsonNode publicKey = webauthnObjectMapper.valueToTree(start.options());
                    auditService.recordPasskeyRegistrationStarted(user.getId());
                    return ResponseEntity.ok(new RegistrationOptionsResponse(start.requestId(), publicKey));
                })
                .orElseGet(() -> ResponseEntity.status(404)
                        .body(new ErrorResponse(404, "NOT_FOUND", "User not found")));
    }

    @PostMapping("/register/finish")
    public ResponseEntity<?> finishRegistration(Authentication authentication,
            @Valid @RequestBody RegistrationFinishRequest request) {
        if (authentication == null || authentication.getPrincipal() == null) {
            return ResponseEntity.status(401)
                    .body(new ErrorResponse(401, "UNAUTHORIZED", "Invalid Credentials"));
        }
        String userId = (String) authentication.getPrincipal();
        Optional<User> userOpt = userRepository.findById(userId);
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(404)
                    .body(new ErrorResponse(404, "NOT_FOUND", "User not found"));
        }
        User user = userOpt.get();
        if (request.credential() == null) {
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse(400, "BAD_REQUEST", "Credential payload required"));
        }
        try {
            PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> credential = webauthnObjectMapper
                    .convertValue(request.credential(), new TypeReference<>() {
                    });
            var saved = webAuthnService.finishRegistration(request.requestId(), credential);
            if (!saved.getUserId().equals(user.getId())) {
                return ResponseEntity.status(403)
                        .body(new ErrorResponse(403, "FORBIDDEN", "Mismatched registration request"));
            }
            auditService.recordPasskeyRegistered(user.getId(), saved.getCredentialId());
            return ResponseEntity.ok(new SimpleMessageResponse("Passkey registered"));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse(400, "BAD_REQUEST", "Unable to process credential"));
        }
    }

    @PostMapping("/login/options")
    public ResponseEntity<?> startLogin(@Valid @RequestBody LoginOptionsRequest request,
            HttpServletRequest httpRequest) {
        String normalizedEmail = request.email() == null ? null : request.email().trim().toLowerCase(Locale.ROOT);
        if (!captchaValidationService.validateCaptcha(request.captchaToken(), resolveClientIp(httpRequest))) {
            auditService.recordPasskeyAuthenticationFailure(normalizedEmail);
            auditService.recordLoginFailure(normalizedEmail);
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse(400, "INVALID_CAPTCHA", "CAPTCHA verification failed. Please try again."));
        }
        if (normalizedEmail == null || normalizedEmail.isBlank()) {
            auditService.recordLoginFailure(normalizedEmail);
            return ResponseEntity.status(401)
                    .body(new ErrorResponse(401, "UNAUTHORIZED", "Invalid Credentials"));
        }
        if (!rateLimiterService.isAllowed(buildLoginRateLimitKey(httpRequest, normalizedEmail))) {
            auditService.recordPasskeyAuthenticationFailure(normalizedEmail);
            auditService.recordLoginFailure(normalizedEmail);
            return ResponseEntity.status(429)
                    .body(new ErrorResponse(429, "TOO_MANY_REQUESTS",
                            "Too many attempts. Please try again later."));
        }
        return userRepository.findByEmail(normalizedEmail)
                .<ResponseEntity<?>>map(user -> {
                    if (!user.isEmailVerified()) {
                        auditService.recordPasskeyAuthenticationFailure(normalizedEmail);
                        auditService.recordLoginFailure(normalizedEmail);
                        return ResponseEntity.status(403)
                                .body(new ErrorResponse(403, "EMAIL_NOT_VERIFIED",
                                        "Please verify your email address before logging in."));
                    }
                    try {
                        WebAuthnService.AssertionStart start = webAuthnService.startAssertion(user.getId(),
                                user.getEmail());
                        JsonNode publicKey = webauthnObjectMapper.valueToTree(start.options());
                        return ResponseEntity.ok(new LoginOptionsResponse(start.requestId(), publicKey));
                    } catch (IllegalStateException ex) {
                        return ResponseEntity.status(400)
                                .body(new ErrorResponse(400, "NO_PASSKEY", "No passkeys registered for this account."));
                    }
                })
                .orElseGet(() -> {
                    auditService.recordPasskeyAuthenticationFailure(normalizedEmail);
                    auditService.recordLoginFailure(normalizedEmail);
                    return ResponseEntity.status(401)
                            .body(new ErrorResponse(401, "UNAUTHORIZED", "Invalid Credentials"));
                });
    }

    @PostMapping("/login/finish")
    public ResponseEntity<?> finishLogin(@Valid @RequestBody LoginFinishRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        if (request.credential() == null) {
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse(400, "BAD_REQUEST", "Credential payload required"));
        }
        try {
            PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential = webauthnObjectMapper
                    .convertValue(request.credential(), new TypeReference<>() {
                    });
            WebAuthnService.AssertionFinish finish = webAuthnService.finishAssertion(request.requestId(), credential);
            Optional<User> userOpt = userRepository.findById(finish.userId());
            String username = finish.result().getUsername();
            if (userOpt.isEmpty()) {
                auditService.recordLoginFailure(username);
                return ResponseEntity.status(404)
                        .body(new ErrorResponse(404, "NOT_FOUND", "User not found"));
            }
            User user = userOpt.get();
            if (!user.isEmailVerified()) {
                auditService.recordPasskeyAuthenticationFailure(username);
                auditService.recordLoginFailure(username);
                return ResponseEntity.status(403)
                        .body(new ErrorResponse(403, "EMAIL_NOT_VERIFIED",
                                "Please verify your email address before logging in."));
            }
            AuthSessionService.Session session = authSessionService.startSession(user, httpRequest, httpResponse);
            auditService.recordPasskeyAuthenticationSuccess(user.getId());
            auditService.recordLoginSuccess(user.getId());
            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, session.cookie().toString())
                    .header(session.csrfToken().getHeaderName(), session.csrfToken().getToken())
                    .body(new LoginResponse(PublicUser.fromUser(user)));
        } catch (IllegalArgumentException ex) {
            auditService.recordPasskeyAuthenticationFailure(request.requestId());
            auditService.recordLoginFailure(request.requestId());
            return ResponseEntity.status(400)
                    .body(new ErrorResponse(400, "BAD_REQUEST", "Unable to process credential"));
        } catch (Exception ex) {
            auditService.recordPasskeyAuthenticationFailure(request.requestId());
            auditService.recordLoginFailure(request.requestId());
            return ResponseEntity.status(401)
                    .body(new ErrorResponse(401, "UNAUTHORIZED", "Invalid passkey assertion"));
        }
    }

    private String resolveClientIp(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }
        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) {
            return realIp.trim();
        }
        String remote = request.getRemoteAddr();
        return remote == null ? null : remote.trim();
    }

    private String buildLoginRateLimitKey(HttpServletRequest request, String email) {
        return buildRateLimitKey("passkey-login", request, email);
    }

    private String buildRateLimitKey(String prefix, HttpServletRequest request, String identifier) {
        String remoteAddr = request != null && request.getRemoteAddr() != null
                ? request.getRemoteAddr()
                : "unknown";
        String normalized = identifier == null ? "" : identifier.trim().toLowerCase(Locale.ROOT);
        int identifierHash = normalized.isEmpty() ? 0 : normalized.hashCode();
        return prefix + ":" + remoteAddr + ":" + Integer.toHexString(identifierHash);
    }
}
