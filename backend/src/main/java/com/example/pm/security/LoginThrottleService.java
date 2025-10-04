package com.example.pm.security;

import com.example.pm.config.RateLimitProps;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Optional;

@Service
public class LoginThrottleService {

    private static final Logger log = LoggerFactory.getLogger(LoginThrottleService.class);
    private static final int MAX_RETRIES = 3;

    private final LoginThrottleRepository repository;
    private final RateLimitProps rateLimitProps;
    private final Clock clock;

    public LoginThrottleService(LoginThrottleRepository repository, RateLimitProps rateLimitProps) {
        this(repository, rateLimitProps, Clock.systemUTC());
    }

    LoginThrottleService(LoginThrottleRepository repository, RateLimitProps rateLimitProps, Clock clock) {
        this.repository = repository;
        this.rateLimitProps = rateLimitProps;
        this.clock = clock;
    }

    public boolean tryAcquire(String path, String ip, String identifier) {
        String key = buildKey(path, ip, identifier);
        int perMinute = Math.max(1, rateLimitProps.getLogin().getPerMinute());
        int perHour = Math.max(perMinute, rateLimitProps.getLogin().getPerHour());

        for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
            Instant now = clock.instant();
            LoginThrottleEntry entry = repository.findById(key)
                    .orElseGet(() -> new LoginThrottleEntry(key, now));

            boolean allowed = entry.recordAttempt(now, perMinute, perHour);
            try {
                repository.save(entry);
                return allowed;
            } catch (OptimisticLockingFailureException ex) {
                log.debug("Optimistic locking failure for key {} on attempt {}", key, attempt + 1);
            }
        }

        return false;
    }

    String buildKey(String path, String ip, String identifier) {
        String normalizedPath = Optional.ofNullable(path).orElse("").trim().toLowerCase(Locale.ROOT);
        String normalizedIp = Optional.ofNullable(ip).orElse("unknown").trim().toLowerCase(Locale.ROOT);
        String normalizedIdentifier = Optional.ofNullable(identifier).orElse("").trim().toLowerCase(Locale.ROOT);
        String hashedIdentifier = hashIdentifier(normalizedIdentifier);
        return normalizedPath + "|" + normalizedIp + "|" + hashedIdentifier;
    }

    private String hashIdentifier(String identifier) {
        if (identifier.isEmpty()) {
            return "anon";
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(identifier.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}