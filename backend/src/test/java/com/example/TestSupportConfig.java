package com.example;

import com.example.pm.config.CaptchaProps;
import com.example.pm.security.CaptchaValidationService;
import com.example.pm.security.LoginThrottleEntry;
import com.example.pm.security.LoginThrottleRepository;
import com.example.pm.security.LoginThrottleService;
import com.example.pm.security.PasswordVerifier;
import com.example.pm.webauthn.MongoWebAuthnCredentialRepository;
import com.example.pm.webauthn.WebAuthnCredentialRepository;
import com.example.pm.webauthn.WebAuthnService;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.data.mongodb.core.mapping.MongoMappingContext;

import org.mockito.Mockito;

import java.util.Collections;
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
        CaptchaProps props = new CaptchaProps();
        props.setProvider(CaptchaProps.Provider.NONE);
        return props;
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
        return new CaptchaValidationService(captchaProps) {
            @Override
            public boolean validateCaptcha(String token, String remoteIp) {
                return true;
            }
        };
    }

    @Bean
    @Primary
    public WebAuthnCredentialRepository webAuthnCredentialRepository() {
        return Mockito.mock(WebAuthnCredentialRepository.class);
    }

    @Bean
    @Primary
    public MongoWebAuthnCredentialRepository mongoWebAuthnCredentialRepository() {
        MongoWebAuthnCredentialRepository repository = Mockito.mock(MongoWebAuthnCredentialRepository.class);
        Mockito.when(repository.getCredentialIdsForUsername(Mockito.anyString())).thenReturn(Collections.emptySet());
        Mockito.when(repository.getUserHandleForUsername(Mockito.anyString())).thenReturn(Optional.empty());
        Mockito.when(repository.getUsernameForUserHandle(Mockito.any())).thenReturn(Optional.empty());
        Mockito.when(repository.lookup(Mockito.any(), Mockito.any())).thenReturn(Optional.empty());
        Mockito.when(repository.lookupAll(Mockito.any())).thenReturn(Collections.emptySet());
        return repository;
    }

    @Bean
    @Primary
    public WebAuthnService webAuthnService() {
        return Mockito.mock(WebAuthnService.class);
    }

    @Bean
    @Primary
    public PasswordVerifier passwordVerifier() {
        PasswordVerifier verifier = Mockito.mock(PasswordVerifier.class);
        Mockito.when(verifier.verify(Mockito.any(), Mockito.any())).thenReturn(true);
        return verifier;
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
