package com.example.pm.auth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Locale;

@Service
public class PlaceholderSaltService {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final SecretKeySpec secretKeySpec;
    private final Base64.Encoder base64Encoder = Base64.getEncoder();

    public PlaceholderSaltService(
            @Value("${app.auth.placeholder-salt-secret}") String secret
    ) {
        if (secret == null || secret.isBlank()) {
            throw new IllegalArgumentException("Placeholder salt secret must not be blank");
        }
        this.secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM);
    }

    public String fakeSaltFor(String identifier) {
        String normalized = normalizeIdentifier(identifier);
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(secretKeySpec);
            byte[] result = mac.doFinal(normalized.getBytes(StandardCharsets.UTF_8));
            return base64Encoder.encodeToString(result);
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            throw new IllegalStateException("Failed to compute placeholder salt", ex);
        }
    }

    private String normalizeIdentifier(String identifier) {
        if (identifier == null) {
            return "";
        }
        String trimmed = identifier.trim();
        if (trimmed.contains("@")) {
            return trimmed.toLowerCase(Locale.ROOT);
        }
        return trimmed.toLowerCase(Locale.ROOT);
    }
}