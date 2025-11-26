package com.example.pm.auth;

import com.example.pm.auditlog.SecurityAuditService;
import com.example.pm.dto.AuthDtos.*;
import com.example.pm.exceptions.ErrorResponse;
import com.example.pm.model.User;
import com.example.pm.repo.UserRepository;
import com.example.pm.security.AuthSessionService;
import com.example.pm.security.RateLimiterService;
import com.example.pm.security.TotpService;
import com.example.pm.security.CaptchaValidationService;
import com.example.pm.security.PasswordVerifier;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository users;
    private final AuthSessionService authSessionService;
    private final RateLimiterService rateLimiterService;
    private final TotpService totpService;
    private final SecurityAuditService auditService;
    private final CaptchaValidationService captchaValidationService;
    private final CsrfTokenRepository csrfTokenRepository;
    private final PlaceholderSaltService placeholderSaltService;
    private final EmailVerificationService emailVerificationService;
    private final PasswordVerifier passwordVerifier;

    private static final Pattern AVATAR_DATA_URL_PATTERN = Pattern.compile(
            "^data:(image/(?:png|jpeg|jpg|webp));base64,([A-Za-z0-9+/=\\r\\n]+)$",
            Pattern.CASE_INSENSITIVE
    );
    private static final int MAX_AVATAR_BYTES = 256 * 1024;

    private static final SecureRandom RECOVERY_RANDOM = new SecureRandom();
    private static final char[] RECOVERY_CODE_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".toCharArray();

    public AuthController(UserRepository users,
                          RateLimiterService rateLimiterService, TotpService totpService,
                          SecurityAuditService auditService,
                          CaptchaValidationService captchaValidationService,
                          PlaceholderSaltService placeholderSaltService,
                          EmailVerificationService emailVerificationService,
                          AuthSessionService authSessionService,
                          CsrfTokenRepository csrfTokenRepository,
                          PasswordVerifier passwordVerifier) {
        this.users = users;
        this.authSessionService = authSessionService;
        this.rateLimiterService = rateLimiterService;
        this.totpService = totpService;
        this.auditService = auditService;
        this.captchaValidationService = captchaValidationService;
        this.placeholderSaltService = placeholderSaltService;
        this.emailVerificationService = emailVerificationService;
        this.csrfTokenRepository = csrfTokenRepository;
        this.passwordVerifier = passwordVerifier;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest registerRequest,
                                      HttpServletRequest request) {
        if (!captchaValidationService.validateCaptcha(registerRequest.captchaToken(), resolveClientIp(request))) {
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse(400, "INVALID_CAPTCHA", "CAPTCHA verification failed. Please try again."));
        }
        String normalizedAvatar;
        try {
            normalizedAvatar = normalizeAvatarData(registerRequest.avatarData());
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse(400, "INVALID_AVATAR", ex.getMessage()));
        }
        User newUser = User.fromRegisterRequest(registerRequest);

        newUser.setAvatarData(normalizedAvatar);
        if (users.findByEmail(newUser.getEmail()).isPresent())
            return ResponseEntity.status(409).body(new ErrorResponse(409, "CONFLICT", "Email already exists"));

        if (users.findByUsername(newUser.getUsername()).isPresent())
            return ResponseEntity.status(409).body(new ErrorResponse(409, "CONFLICT", "Username already exists"));
        emailVerificationService.registerPendingUser(newUser);

        return ResponseEntity.ok(new SimpleMessageResponse("Check your inbox to verify your email."));
    }

    @GetMapping("/salt")
    public ResponseEntity<?> salt(@RequestParam String identifier, HttpServletRequest request) {
        String trimmed = identifier == null ? "" : identifier.trim();

        if (!rateLimiterService.isAllowed(buildSaltRateLimitKey(request, trimmed))) {
            return ResponseEntity.status(429)
                    .body(new ErrorResponse(429, "TOO_MANY_REQUESTS",
                            "Too many attempts. Please try again later."));
        }

        if (trimmed.isEmpty()) {
            return ResponseEntity.ok(new SaltResponse(
                    placeholderEmailFor(trimmed),
                    placeholderSaltService.fakeSaltFor(trimmed)
            ));
        }

        String normalizedEmail = trimmed.contains("@") ? trimmed.toLowerCase(Locale.ROOT) : null;

        var user = normalizedEmail != null
                ? users.findByEmail(normalizedEmail)
                : users.findByUsername(trimmed);

        return user
                .<ResponseEntity<?>>map(u -> ResponseEntity.ok(new SaltResponse(u.getEmail(), u.getSaltClient())))
                .orElseGet(() -> ResponseEntity.ok(new SaltResponse(
                        normalizedEmail != null ? normalizedEmail : placeholderEmailFor(trimmed),
                        placeholderSaltService.fakeSaltFor(normalizedEmail != null ? normalizedEmail : trimmed)
                )));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest,
                                   HttpServletRequest request,
                                   HttpServletResponse response) {

        if (!captchaValidationService.validateCaptcha(loginRequest.captchaToken(), resolveClientIp(request))) {
            auditService.recordLoginFailure(loginRequest.email());
            return ResponseEntity.status(400)
                    .body(new ErrorResponse(400, "INVALID_CAPTCHA", "CAPTCHA verification failed. Please try again."));
        }

        String normalizedEmail = loginRequest.email() == null ? null : loginRequest.email().trim().toLowerCase(Locale.ROOT);
        if (normalizedEmail == null || normalizedEmail.isBlank()) {
            return ResponseEntity.status(401)
                    .body(new ErrorResponse(401, "UNAUTHORIZED", "Invalid Credentials"));
        }

        if (!rateLimiterService.isAllowed(buildLoginRateLimitKey(request, normalizedEmail))) {
            auditService.recordLoginFailure(normalizedEmail);
            return ResponseEntity.status(429)
                    .body(new ErrorResponse(429, "TOO_MANY_REQUESTS",
                            "Too many attempts. Please try again later."));
        }

        var userOpt = users.findByEmail(normalizedEmail);
        if (userOpt.isEmpty() || !passwordVerifier.verify(loginRequest.verifier(), userOpt.get().getVerifier())) {
            auditService.recordLoginFailure(normalizedEmail);
            return ResponseEntity.status(401)
                    .body(new ErrorResponse(401, "UNAUTHORIZED", "Invalid Credentials"));
        }

        User user = userOpt.get();

        if (!user.isEmailVerified()) {
            auditService.recordLoginFailure(normalizedEmail);
            return ResponseEntity.status(403)
                    .body(new ErrorResponse(403, "EMAIL_NOT_VERIFIED",
                            "Please verify your email address before logging in."));
        }

        if (user.isMfaEnabled()) {
            boolean usedRecovery = false;
            boolean verified = false;
            if (loginRequest.mfaCode() != null && totpService.verifyCode(user.getMfaSecret(), loginRequest.mfaCode())) {
                verified = true;
            } else if (loginRequest.recoveryCode() != null && consumeRecoveryCode(user, loginRequest.recoveryCode())) {
                verified = true;
                usedRecovery = true;
            }
            if (!verified) {
                auditService.recordLoginFailure(normalizedEmail);
                return ResponseEntity.status(401)
                        .body(new ErrorResponse(401, "UNAUTHORIZED", "Invalid MFA challenge"));
            }
            if (usedRecovery) {
                users.save(user);
            }
        }

        var publicUser = PublicUser.fromUser(user);
        AuthSessionService.Session session = authSessionService.startSession(user, request, response);
        auditService.recordLoginSuccess(user.getId());
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, session.cookie().toString())
                .header(session.csrfToken().getHeaderName(), session.csrfToken().getToken())
                .body(new LoginResponse(publicUser));

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

    @GetMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(@RequestParam("token") String token) {
        EmailVerificationService.VerificationResult result = emailVerificationService.verifyToken(token);
        return switch (result) {
            case VERIFIED -> ResponseEntity.ok(new SimpleMessageResponse("Email address verified."));
            case INVALID_TOKEN -> ResponseEntity.badRequest()
                    .body(new ErrorResponse(400, "INVALID_TOKEN", "Verification link is invalid."));
            case EXPIRED -> ResponseEntity.status(410)
                    .body(new ErrorResponse(410, "TOKEN_EXPIRED", "Verification link has expired."));
        };
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<?> resendVerification(@Valid @RequestBody ResendVerificationRequest request) {
        EmailVerificationService.ResendResult result = emailVerificationService.resendVerification(request.email());
        return switch (result) {
            case SENT -> ResponseEntity.accepted()
                    .body(new SimpleMessageResponse("If an account exists, a verification email has been sent."));
            case USER_NOT_FOUND -> ResponseEntity.accepted()
                    .body(new SimpleMessageResponse("If an account exists, a verification email has been sent."));
            case ALREADY_VERIFIED -> ResponseEntity.status(409)
                    .body(new ErrorResponse(409, "EMAIL_ALREADY_VERIFIED", "Email already verified."));
            case RATE_LIMITED -> ResponseEntity.status(429)
                    .body(new ErrorResponse(429, "TOO_MANY_REQUESTS",
                            "Please wait before requesting another verification email."));
        };
    }

    @GetMapping("/csrf")
    public ResponseEntity<Void> csrf(HttpServletRequest request, HttpServletResponse response) {
        CsrfToken csrfToken = csrfTokenRepository.generateToken(request);
        request.setAttribute(CsrfToken.class.getName(), csrfToken);
        request.setAttribute(csrfToken.getParameterName(), csrfToken);
        csrfTokenRepository.saveToken(csrfToken, request, response);
        return ResponseEntity.ok()
                .header(csrfToken.getHeaderName(), csrfToken.getToken())
                .build();
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request) {
        ResponseCookie cleared = authSessionService.buildClearingCookie(request);
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, cleared.toString())
                .build();
    }

    @PostMapping("/sessions/revoke")
    public ResponseEntity<?> revokeSessions(Authentication authentication) {
        if (authentication == null || authentication.getPrincipal() == null) {
            return ResponseEntity.status(401)
                    .body(new ErrorResponse(401, "UNAUTHORIZED", "Invalid Credentials"));
        }

        String userId = (String) authentication.getPrincipal();
        return users.findById(userId)
                .<ResponseEntity<?>>map(user -> {
                    incrementTokenVersion(user);
                    users.save(user);
                    auditService.recordSessionsRevoked(user.getId(), user.getTokenVersion());
                    return ResponseEntity.ok(new RevokeSessionsResponse(user.getTokenVersion()));
                })
                .orElseGet(() -> ResponseEntity.status(404)
                        .body(new ErrorResponse(404, "NOT FOUND", "User not found")));
    }

    @PostMapping("/master/rotate")
    public ResponseEntity<?> rotateMasterPassword(Authentication authentication,
                                                  @Valid @RequestBody RotateMasterPasswordRequest request) {
        if (authentication == null || authentication.getPrincipal() == null) {
            return ResponseEntity.status(401)
                    .body(new ErrorResponse(401, "UNAUTHORIZED", "Invalid Credentials"));
        }

        String userId = (String) authentication.getPrincipal();
        return users.findById(userId)
                .<ResponseEntity<?>>map(user -> {
                    if (!normalizedEquals(user.getVerifier(), request.currentVerifier())) {
                        return ResponseEntity.status(403)
                                .body(new ErrorResponse(403, "FORBIDDEN", "Verifier mismatch"));
                    }

                    user.setVerifier(request.newVerifier());
                    user.setSaltClient(request.newSaltClient());
                    user.setDekEncrypted(request.newDekEncrypted());
                    user.setDekNonce(request.newDekNonce());
                    user.setMasterPasswordLastRotated(Instant.now());

                    boolean invalidated = request.invalidateSessions();
                    if (invalidated) {
                        incrementTokenVersion(user);
                    }

                    users.save(user);
                    auditService.recordMasterPasswordRotation(user.getId(), invalidated);

                    return ResponseEntity.ok(new RotateMasterPasswordResponse(
                            user.getMasterPasswordLastRotated(),
                            invalidated
                    ));
                })
                .orElseGet(() -> ResponseEntity.status(404)
                        .body(new ErrorResponse(404, "NOT FOUND", "User not found")));
    }

    @PostMapping("/master/reset")
    public ResponseEntity<?> resetMasterPassword(@Valid @RequestBody ResetMasterPasswordRequest request) {
        String normalizedEmail = request.email() == null ? null : request.email().trim().toLowerCase(Locale.ROOT);
        if (normalizedEmail == null || normalizedEmail.isBlank()) {
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse(400, "BAD_REQUEST", "Email required"));
        }

        return users.findByEmail(normalizedEmail)
                .<ResponseEntity<?>>map(user -> {
                    if (!consumeRecoveryCode(user, request.recoveryCode())) {
                        auditService.recordLoginFailure(normalizedEmail);
                        return ResponseEntity.status(403)
                                .body(new ErrorResponse(403, "FORBIDDEN", "Invalid recovery code"));
                    }

                    user.setVerifier(request.newVerifier());
                    user.setSaltClient(request.newSaltClient());
                    user.setDekEncrypted(request.newDekEncrypted());
                    user.setDekNonce(request.newDekNonce());
                    user.setMasterPasswordLastRotated(Instant.now());
                    incrementTokenVersion(user);

                    if (request.disableMfa()) {
                        disableMfaState(user);
                    }

                    users.save(user);
                    auditService.recordMasterPasswordReset(user.getId(), request.disableMfa());
                    auditService.recordSessionsRevoked(user.getId(), user.getTokenVersion());

                    return ResponseEntity.ok(new SimpleMessageResponse("Master password reset"));
                })
                .orElseGet(() -> ResponseEntity.status(404)
                        .body(new ErrorResponse(404, "NOT FOUND", "User not found")));
    }

    @PostMapping("/mfa/enroll")
    public ResponseEntity<?> enrollMfa(Authentication authentication) {
        if (authentication == null || authentication.getPrincipal() == null) {
            return ResponseEntity.status(401)
                    .body(new ErrorResponse(401, "UNAUTHORIZED", "Invalid Credentials"));
        }

        String userId = (String) authentication.getPrincipal();
        return users.findById(userId)
                .<ResponseEntity<?>>map(user -> {
                    String secret = totpService.generateSecret();
                    List<String> recoveryCodes = generateRecoveryCodes();
                    user.setMfaSecret(secret);
                    user.setMfaEnabled(false);
                    user.setMfaRecoveryCodes(hashRecoveryCodes(recoveryCodes));
                    users.save(user);
                    auditService.recordMfaEnrollmentStarted(user.getId());

                    return ResponseEntity.ok(new MfaEnrollmentResponse(
                            secret,
                            totpService.buildOtpAuthUrl(user.getEmail(), secret),
                            recoveryCodes
                    ));
                })
                .orElseGet(() -> ResponseEntity.status(404)
                        .body(new ErrorResponse(404, "NOT FOUND", "User not found")));
    }

    @PostMapping("/mfa/activate")
    public ResponseEntity<?> activateMfa(Authentication authentication,
                                         @Valid @RequestBody MfaActivationRequest request) {
        if (authentication == null || authentication.getPrincipal() == null) {
            return ResponseEntity.status(401)
                    .body(new ErrorResponse(401, "UNAUTHORIZED", "Invalid Credentials"));
        }
        String userId = (String) authentication.getPrincipal();
        return users.findById(userId)
                .<ResponseEntity<?>>map(user -> {
                    if (user.getMfaSecret() == null) {
                        return ResponseEntity.status(400)
                                .body(new ErrorResponse(400, "BAD_REQUEST", "MFA enrollment required"));
                    }
                    if (!totpService.verifyCode(user.getMfaSecret(), request.code())) {
                        return ResponseEntity.status(403)
                                .body(new ErrorResponse(403, "FORBIDDEN", "Invalid MFA code"));
                    }
                    user.setMfaEnabled(true);
                    user.setMfaEnabledAt(Instant.now());
                    users.save(user);
                    auditService.recordMfaEnabled(user.getId());
                    return ResponseEntity.ok(new MfaStatusResponse(true, user.getMfaEnabledAt(),
                            user.getMfaRecoveryCodes() != null ? user.getMfaRecoveryCodes().size() : 0));
                })
                .orElseGet(() -> ResponseEntity.status(404)
                        .body(new ErrorResponse(404, "NOT FOUND", "User not found")));
    }

    @PostMapping("/mfa/disable")
    public ResponseEntity<?> disableMfa(Authentication authentication,
                                        @RequestBody MfaDisableRequest request) {
        if (authentication == null || authentication.getPrincipal() == null) {
            return ResponseEntity.status(401)
                    .body(new ErrorResponse(401, "UNAUTHORIZED", "Invalid Credentials"));
        }

        String userId = (String) authentication.getPrincipal();
        return users.findById(userId)
                .<ResponseEntity<?>>map(user -> {
                    if (!user.isMfaEnabled()) {
                        return ResponseEntity.ok(new MfaStatusResponse(false, null, 0));
                    }
                    boolean viaRecovery = false;
                    boolean verified = false;
                    if (request != null && request.code() != null
                            && totpService.verifyCode(user.getMfaSecret(), request.code())) {
                        verified = true;
                    } else if (request != null && request.recoveryCode() != null
                            && consumeRecoveryCode(user, request.recoveryCode())) {
                        verified = true;
                        viaRecovery = true;
                    }
                    if (!verified) {
                        return ResponseEntity.status(403)
                                .body(new ErrorResponse(403, "FORBIDDEN", "Invalid MFA challenge"));
                    }

                    disableMfaState(user);
                    users.save(user);
                    auditService.recordMfaDisabled(user.getId(), viaRecovery);
                    return ResponseEntity.ok(new MfaStatusResponse(false, null, 0));
                })
                .orElseGet(() -> ResponseEntity.status(404)
                        .body(new ErrorResponse(404, "NOT FOUND", "User not found")));
    }

    @GetMapping("/mfa/status")
    public ResponseEntity<?> mfaStatus(Authentication authentication) {
        if (authentication == null || authentication.getPrincipal() == null) {
            return ResponseEntity.status(401)
                    .body(new ErrorResponse(401, "UNAUTHORIZED", "Invalid Credentials"));
        }

        String userId = (String) authentication.getPrincipal();
        return users.findById(userId)
                .<ResponseEntity<?>>map(user -> ResponseEntity.ok(
                        new MfaStatusResponse(user.isMfaEnabled(), user.getMfaEnabledAt(),
                                user.getMfaRecoveryCodes() != null ? user.getMfaRecoveryCodes().size() : 0)))
                .orElseGet(() -> ResponseEntity.status(404)
                        .body(new ErrorResponse(404, "NOT FOUND", "User not found")));
    }

    private List<String> generateRecoveryCodes() {
        List<String> codes = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            codes.add(generateRecoveryCode());
        }
        return codes;
    }

    private String generateRecoveryCode() {
        StringBuilder sb = new StringBuilder(11);
        for (int i = 0; i < 10; i++) {
            int idx = RECOVERY_RANDOM.nextInt(RECOVERY_CODE_CHARS.length);
            sb.append(RECOVERY_CODE_CHARS[idx]);
            if (i == 4) {
                sb.append('-');
            }
        }
        return sb.toString();
    }

    private List<String> hashRecoveryCodes(List<String> codes) {
        if (codes == null) {
            return Collections.emptyList();
        }
        List<String> hashed = new ArrayList<>(codes.size());
        for (String code : codes) {
            hashed.add(hashRecoveryCode(code));
        }
        return hashed;
    }

    private String hashRecoveryCode(String code) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(code.trim().toUpperCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private boolean consumeRecoveryCode(User user, String recoveryCode) {
        if (recoveryCode == null || recoveryCode.isBlank() || user.getMfaRecoveryCodes() == null
                || user.getMfaRecoveryCodes().isEmpty()) {
            return false;
        }
        String hashed = hashRecoveryCode(recoveryCode);
        List<String> existing = new ArrayList<>(user.getMfaRecoveryCodes());
        boolean removed = existing.remove(hashed);
        if (removed) {
            user.setMfaRecoveryCodes(existing);
        }
        return removed;
    }

    private void disableMfaState(User user) {
        user.setMfaEnabled(false);
        user.setMfaSecret(null);
        user.setMfaRecoveryCodes(Collections.emptyList());
        user.setMfaEnabledAt(null);
    }

    private void incrementTokenVersion(User user) {
        int current = user.getTokenVersion();
        user.setTokenVersion(current + 1);
    }

    private boolean normalizedEquals(String left, String right) {
        if (left == null || right == null) {
            return false;
        }
        String normalizedLeft = left.trim();
        String normalizedRight = right.trim();
        byte[] leftBytes = normalizedLeft.getBytes(StandardCharsets.UTF_8);
        byte[] rightBytes = normalizedRight.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(leftBytes, rightBytes);
    }

    private String buildSaltRateLimitKey(HttpServletRequest request, String identifier) {
        return buildRateLimitKey("salt", request, identifier);
    }

    private String buildLoginRateLimitKey(HttpServletRequest request, String email) {
        return buildRateLimitKey("login", request, email);
    }

    private String buildRateLimitKey(String prefix, HttpServletRequest request, String identifier) {
        String remoteAddr = request != null && request.getRemoteAddr() != null
                ? request.getRemoteAddr()
                : "unknown";
        String normalized = identifier == null ? "" : identifier.trim().toLowerCase(Locale.ROOT);
        int identifierHash = normalized.isEmpty() ? 0 : normalized.hashCode();
        return prefix + ":" + remoteAddr + ":" + Integer.toHexString(identifierHash);
    }

    private static String placeholderEmailFor(String identifier) {
        if (identifier == null || identifier.isBlank()) {
            return "invalid@example.invalid";
        }

        String normalized = identifier.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9._-]", "");
        if (normalized.isBlank()) {
            normalized = "user";
        }
        return normalized + "@example.invalid";
    }

    @GetMapping("/me")
    public ResponseEntity<?> me(Authentication authentication) {
        if (authentication == null || authentication.getPrincipal() == null) {
            return ResponseEntity.status(401)
                    .body(new ErrorResponse(401, "UNAUTHORIZED", "Invalid Credentials"));
        }

        String userId = (String) authentication.getPrincipal();
        return users.findById(userId)
                .<ResponseEntity<?>>map(user -> ResponseEntity.ok(PublicUser.fromUser(user)))
                .orElseGet(() -> ResponseEntity.status(404)
                        .body(new ErrorResponse(404, "NOT FOUND", "User not found")));
    }

    @PutMapping("/profile/avatar")
    public ResponseEntity<?> updateAvatar(Authentication authentication,
                                          @RequestBody AvatarUploadRequest request) {
        if (authentication == null || authentication.getPrincipal() == null) {
            return ResponseEntity.status(401)
                    .body(new ErrorResponse(401, "UNAUTHORIZED", "Invalid Credentials"));
        }

        String userId = (String) authentication.getPrincipal();
        return users.findById(userId)
                .<ResponseEntity<?>>map(user -> {
                    String normalized;
                    try {
                        normalized = normalizeAvatarData(request.avatarData());
                    } catch (IllegalArgumentException ex) {
                        return ResponseEntity.badRequest()
                                .body(new ErrorResponse(400, "INVALID_AVATAR", ex.getMessage()));
                    }

                    user.setAvatarData(normalized);
                    users.save(user);
                    return ResponseEntity.ok(PublicUser.fromUser(user));
                })
                .orElseGet(() -> ResponseEntity.status(404)
                        .body(new ErrorResponse(404, "NOT FOUND", "User not found")));
    }

    private String normalizeAvatarData(String avatarData) {
        if (avatarData == null) {
            return null;
        }

        String trimmed = avatarData.trim();
        if (trimmed.isEmpty()) {
            return null;
        }

        Matcher matcher = AVATAR_DATA_URL_PATTERN.matcher(trimmed);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Avatar must be a PNG, JPEG, or WebP data URL.");
        }

        String mediaType = matcher.group(1).toLowerCase(Locale.ROOT);
        if ("image/jpg".equals(mediaType)) {
            mediaType = "image/jpeg";
        }

        String base64 = matcher.group(2).replaceAll("\\s", "");
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Avatar data is not valid base64.");
        }

        if (decoded.length > MAX_AVATAR_BYTES) {
            throw new IllegalArgumentException("Avatar must be 256 KB or smaller.");
        }

        String normalizedBase64 = Base64.getEncoder().encodeToString(decoded);
        return "data:" + mediaType + ";base64," + normalizedBase64;
    }
}
