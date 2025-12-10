package com.example.pm.security;

import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
@ConditionalOnBean(MongoTemplate.class)
@SuppressWarnings("null") // Suppress Spring null-safety false positives
class MongoLoginThrottleRepository implements LoginThrottleRepository {

    private final MongoTemplate mongoTemplate;

    MongoLoginThrottleRepository(MongoTemplate mongoTemplate) {
        this.mongoTemplate = mongoTemplate;
    }

    @Override
    public Optional<LoginThrottleEntry> findById(String id) {
        if (id == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(mongoTemplate.findById(id, LoginThrottleEntry.class));
    }

    @Override
    public LoginThrottleEntry save(LoginThrottleEntry entry) {
        mongoTemplate.save(entry);
        return entry;
    }
}
