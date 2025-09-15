package com.example.pm.auth;

import com.example.pm.dto.AuthDtos.*;
import com.example.pm.exceptions.ErrorResponse;
import com.example.pm.model.User;
import com.example.pm.repo.UserRepository;
import com.example.pm.security.JwtService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController @RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository users;
    private final JwtService jwt;

    public AuthController(UserRepository users, JwtService jwt) {
        this.users = users;
        this.jwt = jwt;
    }

    // Register endpoint Handler
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest registerRequest) {

        if (users.findByEmail(registerRequest.email()).isPresent())
            return ResponseEntity.status(409).body(new ErrorResponse(409,"CONFLICT","Email already exists"));

        User newUser = User.fromRegisterRequest(registerRequest);
        users.save(newUser);

        return ResponseEntity.ok(new RegisterResponse(newUser.getId()));
    }

    // Salt endpoint Handler
    @GetMapping("/salt")
    public ResponseEntity<?> salt(@RequestParam String email) {
        return users.findByEmail(email)
                .<ResponseEntity<?>>map(user -> ResponseEntity.ok(new SaltResponse(user.getSaltClient())))
                .orElseGet(() -> ResponseEntity.status(404).body(new ErrorResponse(404,"NOT FOUND","Invalid Email - User not found")));
    }

    // Login endpoint Handler
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {

        return users.findByEmail(loginRequest.email())
                .filter(user -> user.getVerifier().equals(loginRequest.verifier()))
                .<ResponseEntity<?>>map(user -> {
                    String token = jwt.generate(user.getId());
                    var publicUser = PublicUser.fromUser(user);
                    return ResponseEntity.ok(new LoginResponse(token, publicUser));
                })
                .orElseGet(() -> ResponseEntity.status(401)
                        .body(new ErrorResponse(401, "UNAUTHORIZED", "Invalid Credentials")));

    }
}
