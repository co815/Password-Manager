package com.example.pm.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

@Component
public class RateLimiterService {

    private final int maxRequests;
    private final Duration window;
    private final Map<String, RequestWindow> windows = new ConcurrentHashMap<>();

    public RateLimiterService(
            @Value("${security.salt.rate-limit.requests:10}") int maxRequests,
            @Value("${security.salt.rate-limit.window-seconds:60}") long windowSeconds
    ) {
        this.maxRequests = Math.max(1, maxRequests);
        this.window = Duration.ofSeconds(Math.max(1, windowSeconds));
    }

    public boolean isAllowed(String key) {
        if (key == null || key.isBlank()) {
            return true;
        }

        Instant now = Instant.now();
        AtomicBoolean allowed = new AtomicBoolean(true);

        windows.compute(key, (k, current) -> {
            if (current == null || now.isAfter(current.windowStart().plus(window))) {
                allowed.set(true);
                return new RequestWindow(now, 1);
            }

            if (current.count() >= maxRequests) {
                allowed.set(false);
                return current;
            }

            allowed.set(true);
            return new RequestWindow(current.windowStart(), current.count() + 1);
        });

        return allowed.get();
    }

    private record RequestWindow(Instant windowStart, int count) { }
}