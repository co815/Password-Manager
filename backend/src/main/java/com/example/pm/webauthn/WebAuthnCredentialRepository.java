package com.example.pm.webauthn;

import com.example.pm.webauthn.model.WebAuthnCredential;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;
import java.util.Optional;

public interface WebAuthnCredentialRepository extends MongoRepository<WebAuthnCredential, String> {
    List<WebAuthnCredential> findByUserId(String userId);
    Optional<WebAuthnCredential> findByCredentialId(String credentialId);
}
