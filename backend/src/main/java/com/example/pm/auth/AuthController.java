package com.example.pm.auth;

import com.example.pm.config.AuthCookieProps;
import com.example.pm.dto.AuthDtos.*;
import com.example.pm.exceptions.ErrorResponse;
import com.example.pm.model.User;
import com.example.pm.repo.UserRepository;
import com.example.pm.security.JwtService;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.Locale;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository users;
    private final JwtService jwt;
    private final AuthCookieProps authCookieProps;

    public AuthController(UserRepository users, JwtService jwt, AuthCookieProps authCookieProps) {
        this.users = users;
        this.jwt = jwt;
        this.authCookieProps = authCookieProps;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest registerRequest) {
        User newUser = User.fromRegisterRequest(registerRequest);

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

        return users.findByEmail(trimmed.toLowerCase(Locale.ROOT))
                .or(() -> users.findByUsername(trimmed))
                .<ResponseEntity<?>>map(user -> ResponseEntity.ok(new SaltResponse(user.getEmail(), user.getSaltClient())))
                .orElseGet(() -> ResponseEntity.status(404)
                        .body(new ErrorResponse(404, "NOT FOUND", "Invalid identifier - User not found")));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {

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
                    ResponseCookie cookie = buildAccessTokenCookie(token, jwt.getExpiry());
                    return ResponseEntity.ok()
                            .header(HttpHeaders.SET_COOKIE, cookie.toString())
                            .body(new LoginResponse(publicUser));
                })
                .orElseGet(() -> ResponseEntity.status(401)
                        .body(new ErrorResponse(401, "UNAUTHORIZED", "Invalid Credentials")));

    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout() {
        ResponseCookie cleared = buildAccessTokenCookie("", Duration.ZERO);
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, cleared.toString())
                .build();
    }

    private ResponseCookie buildAccessTokenCookie(String value, Duration maxAge) {
        ResponseCookie.ResponseCookieBuilder builder = ResponseCookie.from("accessToken", value != null ? value : "")
                .path("/")
                .httpOnly(true)
                .secure(true);

        if (maxAge != null) {
            if (maxAge.isZero() || maxAge.isNegative()) {
                builder.maxAge(Duration.ZERO);
            } else {
                builder.maxAge(maxAge);
            }
        }


        String sameSite = authCookieProps.getSameSiteAttribute();
        if (sameSite != null && !sameSite.isBlank()) {
            builder.sameSite(sameSite);
        }
        return builder.build();
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
}
