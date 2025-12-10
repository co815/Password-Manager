package com.example.pm.webauthn;

import com.example.pm.model.User;
import com.example.pm.repo.UserRepository;
import com.example.pm.webauthn.model.WebAuthnCredential;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.AuthenticatorTransport;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialType;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Component
@Profile("!test")
@SuppressWarnings({ "deprecation", "null" }) // WebAuthn library deprecates backup state methods; suppress null-safety
                                             // false positives
public class MongoWebAuthnCredentialRepository implements CredentialRepository {

    private final ObjectProvider<WebAuthnCredentialRepository> credentialsProvider;
    private final ObjectProvider<UserRepository> userRepositoryProvider;

    public MongoWebAuthnCredentialRepository(ObjectProvider<WebAuthnCredentialRepository> credentials,
            ObjectProvider<UserRepository> userRepository) {
        this.credentialsProvider = credentials;
        this.userRepositoryProvider = userRepository;
    }

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        WebAuthnCredentialRepository credentialRepository = credentialsProvider.getIfAvailable();
        if (credentialRepository == null) {
            return Collections.emptySet();
        }
        return findUserByEmail(username)
                .map(user -> credentialRepository.findByUserId(user.getId()).stream()
                        .map(this::toDescriptor)
                        .collect(Collectors.toSet()))
                .orElseGet(Collections::emptySet);
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        if (username == null || username.isBlank()) {
            return Optional.empty();
        }
        return findUserByEmail(username)
                .map(User::getId)
                .map(this::userHandleFromUserId);
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        if (userHandle == null) {
            return Optional.empty();
        }
        String userId = userIdFromHandle(userHandle);
        UserRepository userRepository = userRepositoryProvider.getIfAvailable();
        if (userRepository == null) {
            return Optional.empty();
        }
        return userRepository.findById(userId).map(User::getEmail);
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        if (credentialId == null) {
            return Optional.empty();
        }
        WebAuthnCredentialRepository credentialRepository = credentialsProvider.getIfAvailable();
        if (credentialRepository == null) {
            return Optional.empty();
        }
        Optional<WebAuthnCredential> credential = credentialRepository.findByCredentialId(credentialId.getBase64());
        if (credential.isEmpty()) {
            return Optional.empty();
        }
        if (userHandle != null) {
            String userId = userIdFromHandle(userHandle);
            if (!credential.get().getUserId().equals(userId)) {
                return Optional.empty();
            }
        }
        return credential.map(this::toRegisteredCredential);
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        if (credentialId == null) {
            return Collections.emptySet();
        }
        WebAuthnCredentialRepository credentialRepository = credentialsProvider.getIfAvailable();
        if (credentialRepository == null) {
            return Collections.emptySet();
        }
        return credentialRepository.findByCredentialId(credentialId.getBase64())
                .map(this::toRegisteredCredential)
                .map(Set::of)
                .orElseGet(Collections::emptySet);
    }

    private Optional<User> findUserByEmail(String email) {
        UserRepository userRepository = userRepositoryProvider.getIfAvailable();
        if (userRepository == null) {
            return Optional.empty();
        }
        if (email == null) {
            return Optional.empty();
        }
        String normalized = email.trim().toLowerCase(Locale.ROOT);
        if (normalized.isBlank()) {
            return Optional.empty();
        }
        return userRepository.findByEmail(normalized);
    }

    private RegisteredCredential toRegisteredCredential(WebAuthnCredential credential) {
        RegisteredCredential.RegisteredCredentialBuilder builder = RegisteredCredential.builder()
                .credentialId(ByteArray.fromBase64(credential.getCredentialId()))
                .userHandle(userHandleFromUserId(credential.getUserId()))
                .publicKeyCose(ByteArray.fromBase64(credential.getPublicKeyCose()))
                .signatureCount(credential.getSignCount());

        if (credential.getBackupEligible() != null) {
            builder.backupEligible(credential.getBackupEligible());
        }
        if (credential.getBackedUp() != null) {
            builder.backupState(credential.getBackedUp());
        }
        return builder.build();
    }

    private PublicKeyCredentialDescriptor toDescriptor(WebAuthnCredential credential) {
        PublicKeyCredentialDescriptor.PublicKeyCredentialDescriptorBuilder builder = PublicKeyCredentialDescriptor
                .builder()
                .id(ByteArray.fromBase64(credential.getCredentialId()))
                .type(PublicKeyCredentialType.PUBLIC_KEY);
        if (credential.getTransports() != null && !credential.getTransports().isEmpty()) {
            builder.transports(credential.getTransports().stream()
                    .filter(transport -> transport != null && !transport.isBlank())
                    .map(String::trim)
                    .map(String::toLowerCase)
                    .map(AuthenticatorTransport::of)
                    .collect(Collectors.toSet()));
        }
        return builder.build();
    }

    private ByteArray userHandleFromUserId(String userId) {
        return new ByteArray(userId.getBytes(StandardCharsets.UTF_8));
    }

    private String userIdFromHandle(ByteArray userHandle) {
        return new String(userHandle.getBytes(), StandardCharsets.UTF_8);
    }
}