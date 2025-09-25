package com.example.pm;

import com.example.pm.security.RateLimiterService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.data.mongodb.core.mapping.MongoMappingContext;

@TestConfiguration
public class TestSupportConfig {

    @Bean
    RateLimiterService testRateLimiterService(
            @Value("${security.salt.rate-limit.requests:10}") int maxRequests,
            @Value("${security.salt.rate-limit.window-seconds:60}") long windowSeconds
    ) {
        return new RateLimiterService(maxRequests, windowSeconds);
    }

    @Bean
    MongoMappingContext mongoMappingContext() {
        return new MongoMappingContext();
    }
}