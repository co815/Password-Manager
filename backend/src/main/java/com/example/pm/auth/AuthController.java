package com.example.pm.auth;

import com.example.pm.config.AuthCookieProps;
import com.example.pm.dto.AuthDtos.*;
import com.example.pm.exceptions.ErrorResponse;
import com.example.pm.model.User;
import com.example.pm.repo.UserRepository;
import com.example.pm.security.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Value;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository users;
    private final JwtService jwt;
    private final AuthCookieProps authCookieProps;
    private final boolean sslEnabled;

    private static final Pattern AVATAR_DATA_URL_PATTERN = Pattern.compile(
            "^data:(image/(?:png|jpeg|jpg|webp));base64,([A-Za-z0-9+/=\\r\\n]+)$",
            Pattern.CASE_INSENSITIVE
    );
    private static final int MAX_AVATAR_BYTES = 256 * 1024;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public AuthController(UserRepository users, JwtService jwt, AuthCookieProps authCookieProps,
                          @Value("${server.ssl.enabled:true}") boolean sslEnabled) {
        this.users = users;
        this.jwt = jwt;
        this.authCookieProps = authCookieProps;
        this.sslEnabled = sslEnabled;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest registerRequest) {
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
        users.save(newUser);

        return ResponseEntity.ok(new RegisterResponse(newUser.getId()));
    }

    @GetMapping("/salt")
    public ResponseEntity<?> salt(@RequestParam String identifier) {
        String trimmed = identifier == null ? "" : identifier.trim();
        if (trimmed.isEmpty()) {
            return ResponseEntity.status(404)
                    .body(new ErrorResponse(404, "NOT FOUND", "Invalid identifier - User not found"));
        }

        String normalizedEmail = trimmed.contains("@") ? trimmed.toLowerCase(Locale.ROOT) : null;

        var user = normalizedEmail != null
                ? users.findByEmail(normalizedEmail)
                : users.findByUsername(trimmed);

        return user
                .<ResponseEntity<?>>map(u -> ResponseEntity.ok(new SaltResponse(u.getEmail(), u.getSaltClient())))
                .orElseGet(() -> ResponseEntity.ok(new SaltResponse(
                        normalizedEmail != null ? normalizedEmail : placeholderEmailFor(trimmed),
                        fakeSalt()
                )));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest,
                                   HttpServletRequest request) {

        String normalizedEmail = loginRequest.email() == null ? null : loginRequest.email().trim().toLowerCase(Locale.ROOT);
        if (normalizedEmail == null || normalizedEmail.isBlank()) {
            return ResponseEntity.status(401)
                    .body(new ErrorResponse(401, "UNAUTHORIZED", "Invalid Credentials"));
        }

        return users.findByEmail(normalizedEmail)
                .filter(user -> user.getVerifier().equals(loginRequest.verifier()))
                .<ResponseEntity<?>>map(user -> {
                    String token = jwt.generate(user.getId());
                    var publicUser = PublicUser.fromUser(user);
                    ResponseCookie cookie = buildAccessTokenCookie(token, jwt.getExpiry(),
                            shouldUseSecureCookie(request));
                    return ResponseEntity.ok()
                            .header(HttpHeaders.SET_COOKIE, cookie.toString())
                            .body(new LoginResponse(publicUser));
                })
                .orElseGet(() -> ResponseEntity.status(401)
                        .body(new ErrorResponse(401, "UNAUTHORIZED", "Invalid Credentials")));

    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request) {
        ResponseCookie cleared = buildAccessTokenCookie("", Duration.ZERO,
                shouldUseSecureCookie(request));
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, cleared.toString())
                .build();
    }

    private ResponseCookie buildAccessTokenCookie(String value, Duration maxAge, boolean secure) {
        ResponseCookie.ResponseCookieBuilder builder = ResponseCookie.from("accessToken", value != null ? value : "")
                .path("/")
                .httpOnly(true)
                .secure(secure);

        if (maxAge != null) {
            if (maxAge.isZero() || maxAge.isNegative()) {
                builder.maxAge(Duration.ZERO);
            } else {
                builder.maxAge(maxAge);
            }
        }

        String sameSite = authCookieProps.getSameSiteAttribute();
        if (!secure && sameSite != null && sameSite.equalsIgnoreCase("None")) {
            sameSite = "Lax";
        }
        if (sameSite != null && !sameSite.isBlank()) {
            builder.sameSite(sameSite);
        }
        return builder.build();
    }

    private boolean shouldUseSecureCookie(HttpServletRequest request) {
        if (!sslEnabled) {
            return false;
        }

        if (request == null) {
            return true;
        }

        if (forwardedProtoIsHttp(request)) {
            return false;
        }

        return request.isSecure();
    }

    private boolean forwardedProtoIsHttp(HttpServletRequest request) {
        String forwardedProto = request.getHeader("X-Forwarded-Proto");
        if (forwardedProto != null) {
            for (String proto : forwardedProto.split(",")) {
                if ("http".equalsIgnoreCase(proto.trim())) {
                    return true;
                }
            }
        }

        String forwarded = request.getHeader("Forwarded");
        if (forwarded != null) {
            for (String segment : forwarded.split(",")) {
                for (String part : segment.split(";")) {
                    String trimmed = part.trim();
                    if (trimmed.regionMatches(true, 0, "proto=", 0, 6)) {
                        String value = trimmed.substring(6).trim();
                        if ("http".equalsIgnoreCase(value)) {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

    private static String fakeSalt() {
        byte[] saltBytes = new byte[16];
        SECURE_RANDOM.nextBytes(saltBytes);
        return Base64.getEncoder().encodeToString(saltBytes);
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
