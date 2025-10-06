package com.example.pm.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.stereotype.Repository;

import jakarta.annotation.PostConstruct;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Repository
@ConditionalOnMissingBean(MongoTemplate.class)
class InMemoryLoginThrottleRepository implements LoginThrottleRepository {

    private static final Logger log = LoggerFactory.getLogger(InMemoryLoginThrottleRepository.class);

    private final ConcurrentMap<String, LoginThrottleEntry> store = new ConcurrentHashMap<>();

    @PostConstruct
    void logInitialization() {
        log.warn("Using in-memory login throttle repository; configure MongoDB for persistent rate limiting.");
    }

    @Override
    public Optional<LoginThrottleEntry> findById(String id) {
        if (id == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(store.get(id));
    }

    @Override
    public LoginThrottleEntry save(LoginThrottleEntry entry) {
        if (entry == null || entry.getId() == null) {
            return entry;
        }
        store.put(entry.getId(), entry);
        return entry;
    }
}