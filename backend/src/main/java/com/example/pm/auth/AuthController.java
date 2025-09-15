package com.example.pm.auth;

import com.example.pm.dto.AuthDtos.*;
import com.example.pm.model.User;
import com.example.pm.repo.UserRepository;
import com.example.pm.security.JwtService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.time.Instant;
import java.util.Map;

@RestController @RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository users;
    private final JwtService jwt;

    public AuthController(UserRepository users, JwtService jwt) {
        this.users = users;
        this.jwt = jwt;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest registerRequest) {

        if (users.findByEmail(registerRequest.email()).isPresent())
            return ResponseEntity.status(409).body(Map.of("error","email_exists"));

        User u = User.builder()
                .email(registerRequest.email())
                .verifier(registerRequest.verifier())
                .saltClient(registerRequest.saltClient())
                .dekEncrypted(registerRequest.dekEncrypted())
                .dekNonce(registerRequest.dekNonce())
                .build();
        users.save(u);

        return ResponseEntity.ok(Map.of("id", u.getId()));
    }

    @GetMapping("/salt")
    public ResponseEntity<?> salt(@RequestParam String email) {
        return users.findByEmail(email)
                .<ResponseEntity<?>>map(u -> ResponseEntity.ok(Map.of("saltClient", u.getSaltClient())))
                .orElseGet(() -> ResponseEntity.status(404).body(Map.of("error","not_found")));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {

        var u = users.findByEmail(loginRequest.email()).orElse(null);

        if (u == null || !u.getVerifier().equals(loginRequest.verifier())) {
            return ResponseEntity.status(401).body(Map.of("error", "invalid_credentials"));
        }

        String token = jwt.generate(u.getId());
        var pub = new PublicUser(u.getId(), u.getEmail(), u.getSaltClient(), u.getDekEncrypted(), u.getDekNonce());

        return ResponseEntity.ok(new LoginResponse(token, pub));
    }
}
