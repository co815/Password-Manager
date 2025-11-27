package com.example.pm.vault;

import com.example.pm.exceptions.ErrorResponse;
import com.example.pm.model.VaultItem;
import com.example.pm.repo.VaultItemRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
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
            if (payload.data() == null || payload.data().isEmpty()) {
                return badRequest("Missing vault data");
            }

            Instant now = Instant.now();
            VaultItem item = new VaultItem();
            item.setUserId(userId);
            item.setData(payload.data());
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
            if (payload.data() == null || payload.data().isEmpty()) {
                return badRequest("Missing vault data");
            }

            return vaultItems.findByIdAndUserId(id, userId)
                    .<ResponseEntity<?>>map(existing -> {
                        existing.setData(payload.data());
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
                        existing.setFavorite(payload.favorite());
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

    private Optional<String> validateCollections(Set<String> collections) {
        if (collections == null) {
            return Optional.empty();
        }
        if (collections.size() > MAX_COLLECTION_COUNT) {
            return Optional.of("Too many collections");
        }
        for (String collection : collections) {
            if (collection == null || collection.isBlank()) {
                continue;
            }
            if (collection.length() > MAX_COLLECTION_NAME_LENGTH) {
                return Optional.of("Collection name too long");
            }
        }
        return Optional.empty();
    }

    private Set<String> normalizeCollections(Set<String> collections) {
        if (collections == null) {
            return new LinkedHashSet<>();
        }
        return collections.stream()
                .filter(c -> c != null && !c.isBlank())
                .map(String::trim)
                .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
    }
}
