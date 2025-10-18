package com.example.pm.webauthn;

import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Component
public class WebAuthnChallengeStore {

    private final Duration ttl;
    private final ConcurrentMap<String, RegistrationChallenge> registrationChallenges = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, AssertionChallenge> assertionChallenges = new ConcurrentHashMap<>();

    public WebAuthnChallengeStore(WebAuthnProperties properties) {
        this.ttl = properties.getChallengeTtl();
    }

    public String storeRegistration(String userId, PublicKeyCredentialCreationOptions options) {
        String requestId = UUID.randomUUID().toString();
        registrationChallenges.put(requestId, new RegistrationChallenge(userId, options, Instant.now()));
        return requestId;
    }

    public Optional<RegistrationChallenge> consumeRegistration(String requestId) {
        if (requestId == null) {
            return Optional.empty();
        }
        RegistrationChallenge challenge = registrationChallenges.remove(requestId);
        if (challenge == null || isExpired(challenge.createdAt())) {
            return Optional.empty();
        }
        return Optional.of(challenge);
    }

    public String storeAssertion(String userId, AssertionRequest request) {
        String requestId = UUID.randomUUID().toString();
        assertionChallenges.put(requestId, new AssertionChallenge(userId, request, Instant.now()));
        return requestId;
    }

    public Optional<AssertionChallenge> consumeAssertion(String requestId) {
        if (requestId == null) {
            return Optional.empty();
        }
        AssertionChallenge challenge = assertionChallenges.remove(requestId);
        if (challenge == null || isExpired(challenge.createdAt())) {
            return Optional.empty();
        }
        return Optional.of(challenge);
    }

    private boolean isExpired(Instant createdAt) {
        if (createdAt == null) {
            return true;
        }
        if (ttl.isZero() || ttl.isNegative()) {
            return false;
        }
        return createdAt.plus(ttl).isBefore(Instant.now());
    }

    public record RegistrationChallenge(String userId, PublicKeyCredentialCreationOptions options, Instant createdAt) {}

    public record AssertionChallenge(String userId, AssertionRequest request, Instant createdAt) {}
}