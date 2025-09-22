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

    // Register endpoint Handler
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest registerRequest) {

        if (users.findByEmail(registerRequest.email()).isPresent())
            return ResponseEntity.status(409).body(new ErrorResponse(409, "CONFLICT", "Email already exists"));

        User newUser = User.fromRegisterRequest(registerRequest);
        users.save(newUser);

        return ResponseEntity.ok(new RegisterResponse(newUser.getId()));
    }

    // Salt endpoint Handler
    @GetMapping("/salt")
    public ResponseEntity<?> salt(@RequestParam String email) {
        return users.findByEmail(email)
                .<ResponseEntity<?>>map(user -> ResponseEntity.ok(new SaltResponse(user.getSaltClient())))
                .orElseGet(() -> ResponseEntity.status(404).body(new ErrorResponse(404, "NOT FOUND", "Invalid Email - User not found")));
    }

    // Login endpoint Handler
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {

        return users.findByEmail(loginRequest.email())
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
