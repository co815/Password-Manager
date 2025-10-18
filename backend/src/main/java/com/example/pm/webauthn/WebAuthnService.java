package com.example.pm.webauthn;

import com.example.pm.webauthn.WebAuthnChallengeStore.AssertionChallenge;
import com.example.pm.webauthn.WebAuthnChallengeStore.RegistrationChallenge;
import com.example.pm.webauthn.model.WebAuthnCredential;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.AuthenticatorTransport;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Service
public class WebAuthnService {

    private final RelyingParty relyingParty;
    private final WebAuthnCredentialRepository credentialRepository;
    private final WebAuthnChallengeStore challengeStore;

    public WebAuthnService(RelyingParty relyingParty,
                           WebAuthnCredentialRepository credentialRepository,
                           WebAuthnChallengeStore challengeStore) {
        this.relyingParty = relyingParty;
        this.credentialRepository = credentialRepository;
        this.challengeStore = challengeStore;
    }

    public RegistrationStart startRegistration(String userId, String email, String displayName) {
        UserIdentity identity = UserIdentity.builder()
                .name(email)
                .displayName(displayName != null && !displayName.isBlank() ? displayName : email)
                .id(userHandleFromUserId(userId))
                .build();

        PublicKeyCredentialCreationOptions options = relyingParty.startRegistration(
                StartRegistrationOptions.builder()
                        .user(identity)
                        .build()
        );

        String requestId = challengeStore.storeRegistration(userId, options);
        return new RegistrationStart(requestId, options);
    }

    public WebAuthnCredential finishRegistration(String requestId,
                                                 PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> response) {
        RegistrationChallenge challenge = challengeStore.consumeRegistration(requestId)
                .orElseThrow(() -> new IllegalArgumentException("Registration request expired or not found"));

        try {
            RegistrationResult result = relyingParty.finishRegistration(FinishRegistrationOptions.builder()
                    .request(challenge.options())
                    .response(response)
                    .build());

            WebAuthnCredential credential = WebAuthnCredential.builder()
                    .userId(challenge.userId())
                    .credentialId(result.getKeyId().getId().getBase64())
                    .publicKeyCose(result.getPublicKeyCose().getBase64())
                    .signCount(result.getSignatureCount())
                    .backupEligible(result.isBackupEligible())
                    .backedUp(result.isBackedUp())
                    .discoverable(result.isDiscoverable().orElse(null))
                    .transports(result.getKeyId().getTransports()
                            .map(transports -> transports.stream().map(AuthenticatorTransport::getId).toList())
                            .orElse(null))
                    .attestationType(result.getAttestationType().name())
                    .aaguid(Optional.ofNullable(result.getAaguid()).map(ByteArray::getHex).orElse(null))
                    .createdAt(Instant.now())
                    .lastUsedAt(null)
                    .build();

            return credentialRepository.save(credential);
        } catch (RegistrationFailedException ex) {
            throw new IllegalArgumentException("Registration validation failed", ex);
        }
    }

    public AssertionStart startAssertion(String userId, String email) {
        List<WebAuthnCredential> credentials = credentialRepository.findByUserId(userId);
        if (credentials.isEmpty()) {
            throw new IllegalStateException("No passkeys registered for this account");
        }
        AssertionRequest assertionRequest = relyingParty.startAssertion(StartAssertionOptions.builder()
                .username(email)
                .build());
        String requestId = challengeStore.storeAssertion(userId, assertionRequest);
        return new AssertionStart(requestId, assertionRequest.getPublicKeyCredentialRequestOptions());
    }

    public AssertionFinish finishAssertion(String requestId,
                                           PublicKeyCredential<com.yubico.webauthn.data.AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> response) {
        AssertionChallenge challenge = challengeStore.consumeAssertion(requestId)
                .orElseThrow(() -> new IllegalArgumentException("Authentication request expired or not found"));

        try {
            AssertionResult result = relyingParty.finishAssertion(FinishAssertionOptions.builder()
                    .request(challenge.request())
                    .response(response)
                    .build());

            if (!result.isSuccess()) {
                throw new IllegalStateException("Authentication assertion failed");
            }

            updateCredentialState(result);

            String resolvedUserId = Optional.ofNullable(result.getCredential().getUserHandle())
                    .map(this::userIdFromHandle)
                    .orElse(challenge.userId());

            return new AssertionFinish(resolvedUserId, result);
        } catch (AssertionFailedException ex) {
            throw new IllegalArgumentException("Assertion validation failed", ex);
        }
    }

    private void updateCredentialState(AssertionResult result) {
        String credentialId = result.getCredential().getCredentialId().getBase64();
        credentialRepository.findByCredentialId(credentialId).ifPresent(credential -> {
            credential.setSignCount(result.getSignatureCount());
            credential.setLastUsedAt(Instant.now());
            if (credential.getBackupEligible() == null) {
                credential.setBackupEligible(result.isBackupEligible());
            }
            credential.setBackedUp(result.isBackedUp());
            credentialRepository.save(credential);
        });
    }

    private ByteArray userHandleFromUserId(String userId) {
        return new ByteArray(userId.getBytes(StandardCharsets.UTF_8));
    }

    private String userIdFromHandle(ByteArray userHandle) {
        return new String(userHandle.getBytes(), StandardCharsets.UTF_8);
    }

    public record RegistrationStart(String requestId, PublicKeyCredentialCreationOptions options) {}

    public record AssertionStart(String requestId, PublicKeyCredentialRequestOptions options) {}

    public record AssertionFinish(String userId, AssertionResult result) {}
}
