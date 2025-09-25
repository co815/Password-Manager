package com.example.pm;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.data.mongodb.core.mapping.MongoMappingContext;

import java.lang.reflect.Proxy;

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
        // Proxy permissive: toate verificările trec (true/0/null).
        return (com.example.pm.security.RateLimiterService)
                Proxy.newProxyInstance(
                        com.example.pm.security.RateLimiterService.class.getClassLoader(),
                        new Class<?>[]{ com.example.pm.security.RateLimiterService.class },
                        (proxy, method, args) -> {
                            Class<?> r = method.getReturnType();
                            if (r == boolean.class || r == Boolean.class) return true;
                            if (r == byte.class || r == short.class || r == int.class || r == long.class) return 0;
                            if (r == float.class || r == double.class) return 0;
                            return null;
                        }
                );
    }
}
