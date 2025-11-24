package com.example.pm.vault;

import com.example.pm.exceptions.ErrorResponse;
import com.example.pm.model.VaultItem;
import com.example.pm.repo.VaultItemRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

@RestController
@RequestMapping("/api/vault")
public class VaultController {

    private static final int MAX_COLLECTION_COUNT = 32;
    private static final int MAX_COLLECTION_NAME_LENGTH = 64;

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
    public ResponseEntity<?> create(Authentication authentication, @RequestBody VaultItemRequest payload) {
        return requireUser(authentication, userId -> {
            Optional<String> validationError = validateRequiredPayload(payload)
                    .or(() -> validateCollections(payload.collections()));
            if (validationError.isPresent()) {
                return badRequest(validationError.get());
            }

            Instant now = Instant.now();
            VaultItem item = new VaultItem();
            item.setUserId(userId);
            item.setTitleCipher(payload.titleCipher());
            item.setTitleNonce(payload.titleNonce());
            item.setUsernameCipher(payload.usernameCipher());
            item.setUsernameNonce(payload.usernameNonce());
            item.setPasswordCipher(payload.passwordCipher());
            item.setPasswordNonce(payload.passwordNonce());
            item.setUrl(payload.url());
            item.setNotesCipher(payload.notesCipher());
            item.setNotesNonce(payload.notesNonce());
            item.setTotpCipher(payload.totpCipher());
            item.setTotpNonce(payload.totpNonce());
            item.setFavorite(Boolean.TRUE.equals(payload.favorite()));
            item.setCollections(normalizeCollections(payload.collections()));
            item.setCreatedAt(now);
            item.setUpdatedAt(now);

            VaultItem saved = vaultItems.save(item);
            return ResponseEntity.ok(saved);
        });
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> update(Authentication authentication,
                                    @PathVariable String id,
                                    @RequestBody VaultItemRequest payload) {
        return requireUser(authentication, userId -> {
            Optional<String> validationError = validateRequiredPayload(payload)
                    .or(() -> validateCollections(payload.collections()));
            if (validationError.isPresent()) {
                return badRequest(validationError.get());
            }

            return vaultItems.findByIdAndUserId(id, userId)
                    .<ResponseEntity<?>>map(existing -> {
                        existing.setTitleCipher(payload.titleCipher());
                        existing.setTitleNonce(payload.titleNonce());
                        existing.setUsernameCipher(payload.usernameCipher());
                        existing.setUsernameNonce(payload.usernameNonce());
                        existing.setPasswordCipher(payload.passwordCipher());
                        existing.setPasswordNonce(payload.passwordNonce());
                        existing.setUrl(payload.url());
                        existing.setNotesCipher(payload.notesCipher());
                        existing.setNotesNonce(payload.notesNonce());
                        existing.setTotpCipher(payload.totpCipher());
                        existing.setTotpNonce(payload.totpNonce());
                        if (payload.collections() != null) {
                            existing.setCollections(normalizeCollections(payload.collections()));
                        }
                        if (payload.favorite() != null) {
                            existing.setFavorite(Boolean.TRUE.equals(payload.favorite()));
                        }
                        existing.setUpdatedAt(Instant.now());

                        VaultItem saved = vaultItems.save(existing);
                        return ResponseEntity.ok(saved);
                    })
                    .orElseGet(this::notFoundResponse);
        });
    }

    @PutMapping("/{id}/metadata")
    public ResponseEntity<?> updateMetadata(Authentication authentication,
                                            @PathVariable String id,
                                            @RequestBody VaultMetadataUpdateRequest payload) {
        if (payload == null) {
            return badRequest("Missing request body");
        }

        Optional<String> validationError = validateCollections(payload.collections());
        if (validationError.isPresent()) {
            return badRequest(validationError.get());
        }

        return requireUser(authentication, userId -> vaultItems.findByIdAndUserId(id, userId)
                .<ResponseEntity<?>>map(existing -> {
                    if (payload.favorite() != null) {
                        existing.setFavorite(Boolean.TRUE.equals(payload.favorite()));
                    }
                    if (payload.collections() != null) {
                        existing.setCollections(normalizeCollections(payload.collections()));
                    }
                    existing.setUpdatedAt(Instant.now());

                    VaultItem saved = vaultItems.save(existing);
                    return ResponseEntity.ok(saved);
                })
                .orElseGet(this::notFoundResponse));
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

    private Optional<String> validateRequiredPayload(VaultItemRequest payload) {
        if (payload == null) {
            return Optional.of("Missing request body");
        }
        if (isBlank(payload.titleCipher()) || isBlank(payload.titleNonce())
                || isBlank(payload.usernameCipher()) || isBlank(payload.usernameNonce())
                || isBlank(payload.passwordCipher()) || isBlank(payload.passwordNonce())) {
            return Optional.of("Missing required fields (title*, username*, password*)");
        }
        return Optional.empty();
    }

    private Optional<String> validateCollections(Collection<String> collections) {
        if (collections == null) {
            return Optional.empty();
        }
        if (collections.size() > MAX_COLLECTION_COUNT) {
            return Optional.of("Too many collections (max " + MAX_COLLECTION_COUNT + ")");
        }
        for (String value : collections) {
            if (value == null) {
                continue;
            }
            String normalized = value.trim();
            if (normalized.length() > MAX_COLLECTION_NAME_LENGTH) {
                return Optional.of("Collection names must be " + MAX_COLLECTION_NAME_LENGTH + " characters or fewer");
            }
        }
        return Optional.empty();
    }

    private Set<String> normalizeCollections(Collection<String> collections) {
        LinkedHashSet<String> normalized = new LinkedHashSet<>();
        if (collections == null) {
            return normalized;
        }
        for (String value : collections) {
            if (value == null) {
                continue;
            }
            String trimmed = value.trim();
            if (!trimmed.isEmpty()) {
                normalized.add(trimmed);
            }
        }
        return normalized;
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
