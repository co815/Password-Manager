package com.example.pm;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.data.mongodb.core.mapping.MongoMappingContext;

import com.example.pm.security.RateLimiterService;

@TestConfiguration
public class TestSupportConfig {

    @Bean
    @Primary
    public RateLimiterService rateLimiterService() {
        return new RateLimiterService(Integer.MAX_VALUE, Long.MAX_VALUE) {
            @Override
            public boolean isAllowed(String key) {
                return true;
            }
        };
    }

    @Bean(name = "mongoMappingContext")
    public MongoMappingContext mongoMappingContext() {
        return new MongoMappingContext();
    }
}