package com.example.pm.security;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class RateLimiterCleanupTask {

    private final RateLimiterService rateLimiterService;

    public RateLimiterCleanupTask(RateLimiterService rateLimiterService) {
        this.rateLimiterService = rateLimiterService;
    }

    @Scheduled(fixedDelay = 60_000)
    public void evictExpiredWindows() {
        rateLimiterService.evictExpiredWindows();
    }
}
