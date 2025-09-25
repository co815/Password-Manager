package com.example.pm;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.data.mongodb.core.mapping.MongoMappingContext;

@TestConfiguration
public class TestSupportConfig {

    @Bean(name = "mongoMappingContext")
    @Primary
    public MongoMappingContext mongoMappingContext() {
        return new MongoMappingContext();
    }

    @Bean
    @Primary
    public com.example.pm.security.RateLimiterService rateLimiterService() {
        return new com.example.pm.security.RateLimiterService(Integer.MAX_VALUE, Long.MAX_VALUE) {
            @Override
            public boolean isAllowed(String key) {
                return true;
            }
        };
    }
}
