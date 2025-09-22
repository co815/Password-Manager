package com.example.pm.credential;

import com.example.pm.dto.CredentialDtos;
import com.example.pm.dto.CredentialDtos.GetAllCredentialResponse;
import com.example.pm.dto.CredentialDtos.PublicCredential;
import com.example.pm.exceptions.ErrorResponse;
import com.example.pm.model.Credential;
import com.example.pm.repo.CredentialRepository;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;
import java.util.function.Function;

@RestController
@RequestMapping({"/api/credentials", "/api/credential"})
public class CredentialController {

    private final CredentialRepository credentials;

    public CredentialController(CredentialRepository credentials) {
        this.credentials = credentials;
    }

    @GetMapping
    public ResponseEntity<?> getAllCredentialsForUser(Authentication authentication) {
        return requireUser(authentication, userId -> {
            List<PublicCredential> publicCredentialList = credentials.findByUserId(userId)
                    .stream()
                    .map(PublicCredential::fromCredential)
                    .toList();
            return ResponseEntity.ok(new GetAllCredentialResponse(publicCredentialList));
        });
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getCredentialById(Authentication authentication, @PathVariable String id) {
        return requireUser(authentication, userId -> credentials.findById(id)
                .filter(c -> userId.equals(c.getUserId()))
                .<ResponseEntity<?>>map(c -> ResponseEntity.ok(PublicCredential.fromCredential(c)))
                .orElseGet(() -> ResponseEntity.status(404)
                        .body(new ErrorResponse(404, "NOT_FOUND", "Credentials Not Found!"))));
    }

    @PostMapping
    public ResponseEntity<?> addCredential(
            Authentication authentication,
            @RequestBody @Valid CredentialDtos.AddCredentialRequest addRequest
    ) {
        return requireUser(authentication, userId -> {
            Optional<Credential> existingForService =
                    credentials.findByUserIdAndService(userId, addRequest.service());

            if (existingForService.isPresent()) {
                return ResponseEntity.status(409)
                        .body(new ErrorResponse(409, "CONFLICT",
                                "Credentials for this service already exist"));
            }

            Credential c = Credential.fromPostRequest(addRequest);
            c.setUserId(userId);

            credentials.save(c);
            return ResponseEntity.ok(PublicCredential.fromCredential(c));
        });
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> updateCredential(
            Authentication authentication,
            @PathVariable String id,
            @RequestBody @Valid CredentialDtos.UpdateCredentialRequest updateRequest
    ) {
        return requireUser(authentication, userId -> credentials.findById(id)
                .filter(credential -> userId.equals(credential.getUserId()))
                .<ResponseEntity<?>>map(existing -> {
                    existing.setService(updateRequest.service());
                    existing.setWebsiteLink(updateRequest.websiteLink());
                    existing.setUsernameEncrypted(updateRequest.usernameEncrypted());
                    existing.setUsernameNonce(updateRequest.usernameNonce());
                    existing.setPasswordEncrypted(updateRequest.passwordEncrypted());
                    existing.setPasswordNonce(updateRequest.passwordNonce());

                    credentials.save(existing);
                    return ResponseEntity.ok(PublicCredential.fromCredential(existing));
                })
                .orElseGet(() -> ResponseEntity.status(404)
                        .body(new ErrorResponse(404, "NOT_FOUND",
                                "The Credentials you want to UPDATE were not found!"))));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteCredential(Authentication authentication, @PathVariable String id) {
        return requireUser(authentication, userId -> credentials.findById(id)
                .filter(credential -> userId.equals(credential.getUserId()))
                .<ResponseEntity<?>>map(credential -> {
                    credentials.delete(credential);
                    return ResponseEntity.noContent().build();
                })
                .orElseGet(() -> ResponseEntity.status(404)
                        .body(new ErrorResponse(404, "NOT_FOUND",
                                "The Credentials you want to DELETE were not found!"))));
    }

    private Optional<String> resolveUserId(Authentication authentication) {
        if (authentication == null) {
            return Optional.empty();
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof String s) {
            return Optional.of(s);
        }
        return Optional.empty();
    }

    private ResponseEntity<ErrorResponse> unauthorizedResponse() {
        return ResponseEntity.status(401)
                .body(new ErrorResponse(401, "UNAUTHORIZED",
                        "Nu esti autentificat sau token invalid"));
    }

    private ResponseEntity<?> requireUser(Authentication authentication,
                                          Function<String, ResponseEntity<?>> handler) {
        var userIdOpt = resolveUserId(authentication);
        if (userIdOpt.isEmpty()) {
            return unauthorizedResponse();
        }
        return handler.apply(userIdOpt.get());
    }
}
