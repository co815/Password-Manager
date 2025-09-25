package com.example.pm.vault;

import com.example.pm.exceptions.ErrorResponse;
import com.example.pm.model.VaultItem;
import com.example.pm.repo.VaultItemRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

@RestController
@RequestMapping("/api/vault")
public class VaultController {

    private final VaultItemRepository vaultItems;

    public VaultController(VaultItemRepository vaultItems) {
        this.vaultItems = vaultItems;
    }

    @GetMapping
    public ResponseEntity<?> list(Authentication authentication) {
        return requireUser(authentication, userId -> {
            List<VaultItem> items = vaultItems.findByUserId(userId);
            return ResponseEntity.ok(items);
        });
    }

    @PostMapping
    public ResponseEntity<?> create(Authentication authentication, @RequestBody VaultItem payload) {
        return requireUser(authentication, userId -> {
            Optional<String> validationError = validateRequiredPayload(payload);
            if (validationError.isPresent()) {
                return badRequest(validationError.get());
            }

            Instant now = Instant.now();
            VaultItem item = new VaultItem();
            item.setUserId(userId);
            item.setTitleCipher(payload.getTitleCipher());
            item.setTitleNonce(payload.getTitleNonce());
            item.setUsernameCipher(payload.getUsernameCipher());
            item.setUsernameNonce(payload.getUsernameNonce());
            item.setPasswordCipher(payload.getPasswordCipher());
            item.setPasswordNonce(payload.getPasswordNonce());
            item.setUrl(payload.getUrl());
            item.setNotesCipher(payload.getNotesCipher());
            item.setNotesNonce(payload.getNotesNonce());
            item.setCreatedAt(now);
            item.setUpdatedAt(now);

            VaultItem saved = vaultItems.save(item);
            return ResponseEntity.ok(saved);
        });
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> update(Authentication authentication,
                                    @PathVariable String id,
                                    @RequestBody VaultItem payload) {
        return requireUser(authentication, userId -> {
            Optional<String> validationError = validateRequiredPayload(payload);
            if (validationError.isPresent()) {
                return badRequest(validationError.get());
            }

            return vaultItems.findByIdAndUserId(id, userId)
                    .<ResponseEntity<?>>map(existing -> {
                        existing.setTitleCipher(payload.getTitleCipher());
                        existing.setTitleNonce(payload.getTitleNonce());
                        existing.setUsernameCipher(payload.getUsernameCipher());
                        existing.setUsernameNonce(payload.getUsernameNonce());
                        existing.setPasswordCipher(payload.getPasswordCipher());
                        existing.setPasswordNonce(payload.getPasswordNonce());
                        existing.setUrl(payload.getUrl());
                        existing.setNotesCipher(payload.getNotesCipher());
                        existing.setNotesNonce(payload.getNotesNonce());
                        existing.setUpdatedAt(Instant.now());

                        VaultItem saved = vaultItems.save(existing);
                        return ResponseEntity.ok(saved);
                    })
                    .orElseGet(this::notFoundResponse);
        });
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(Authentication authentication, @PathVariable String id) {
        return requireUser(authentication, userId -> vaultItems.findByIdAndUserId(id, userId)
                .<ResponseEntity<?>>map(existing -> {
                    vaultItems.delete(existing);
                    return ResponseEntity.ok(Map.of("ok", true));
                })
                .orElseGet(this::notFoundResponse));
    }

    private Optional<String> validateRequiredPayload(VaultItem payload) {
        if (payload == null) {
            return Optional.of("Missing request body");
        }
        if (isBlank(payload.getTitleCipher()) || isBlank(payload.getTitleNonce())
                || isBlank(payload.getUsernameCipher()) || isBlank(payload.getUsernameNonce())
                || isBlank(payload.getPasswordCipher()) || isBlank(payload.getPasswordNonce())) {
            return Optional.of("Missing required fields (title*, username*, password*)");
        }
        return Optional.empty();
    }

    private boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    private ResponseEntity<ErrorResponse> badRequest(String message) {
        return ResponseEntity.badRequest()
                .body(new ErrorResponse(400, "BAD_REQUEST", message));
    }

    private ResponseEntity<ErrorResponse> notFoundResponse() {
        return ResponseEntity.status(404)
                .body(new ErrorResponse(404, "NOT_FOUND", "Vault item not found"));
    }

    private Optional<String> resolveUserId(Authentication authentication) {
        if (authentication == null) {
            return Optional.empty();
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof String s) {
            return Optional.of(s);
        }
        if (principal instanceof org.springframework.security.core.userdetails.UserDetails userDetails) {
            return Optional.ofNullable(userDetails.getUsername());
        }
        if (principal instanceof java.security.Principal namedPrincipal) {
            return Optional.ofNullable(namedPrincipal.getName());
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
