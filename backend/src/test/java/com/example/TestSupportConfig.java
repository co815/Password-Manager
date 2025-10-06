package com.example.pm;

import com.example.pm.config.CaptchaProps;
import com.example.pm.security.CaptchaValidationService;
import com.example.pm.security.LoginThrottleEntry;
import com.example.pm.security.LoginThrottleRepository;
import com.example.pm.security.LoginThrottleService;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.data.mongodb.core.mapping.MongoMappingContext;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

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

    @Bean
    @Primary
    public com.example.pm.config.RateLimitProps rateLimitProps() {
        return new com.example.pm.config.RateLimitProps();
    }

    @Bean
    @Primary
    public CaptchaProps captchaProps() {
        return new CaptchaProps();
    }

    @Bean
    @Primary
    public LoginThrottleRepository loginThrottleRepository() {
        return new InMemoryLoginThrottleRepository();
    }

    @Bean
    @Primary
    public LoginThrottleService loginThrottleService(LoginThrottleRepository repository,
                                                     com.example.pm.config.RateLimitProps rateLimitProps) {
        return new LoginThrottleService(repository, rateLimitProps);
    }

    @Bean
    @Primary
    public CaptchaValidationService captchaValidationService(CaptchaProps captchaProps) {
        return new CaptchaValidationService(captchaProps);
    }

    private static class InMemoryLoginThrottleRepository implements LoginThrottleRepository {

        private final Map<String, LoginThrottleEntry> store = new ConcurrentHashMap<>();

        @Override
        public Optional<LoginThrottleEntry> findById(String id) {
            return Optional.ofNullable(store.get(id));
        }

        @Override
        public LoginThrottleEntry save(LoginThrottleEntry entry) {
            store.put(entry.getId(), entry);
            return entry;
        }
    }
}
