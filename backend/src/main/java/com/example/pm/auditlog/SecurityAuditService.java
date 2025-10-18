package com.example.pm.auditlog;

import com.example.pm.model.AuditLog;
import com.example.pm.repo.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class SecurityAuditService {

    private final AuditLogRepository auditLogRepository;

    public void recordLoginSuccess(String userId) {
        save(userId, "LOGIN_SUCCESS", "User authenticated successfully");
    }

    public void recordLoginFailure(String identifier) {
        save(null, "LOGIN_FAILURE", "Failed login for identifier=" + sanitize(identifier));
    }

    public void recordMasterPasswordRotation(String userId, boolean sessionsInvalidated) {
        save(userId, "MASTER_PASSWORD_ROTATED",
                "Rotated master password" + (sessionsInvalidated ? " and invalidated sessions" : ""));
    }

    public void recordMasterPasswordReset(String userId, boolean disableMfa) {
        save(userId, "MASTER_PASSWORD_RESET",
                "Master password reset via recovery" + (disableMfa ? " with MFA disabled" : ""));
    }

    public void recordMfaEnrollmentStarted(String userId) {
        save(userId, "MFA_ENROLLMENT_STARTED", "Generated new MFA secret and recovery codes");
    }

    public void recordMfaEnabled(String userId) {
        save(userId, "MFA_ENABLED", "Multi-factor authentication activated");
    }

    public void recordMfaDisabled(String userId, boolean viaRecoveryCode) {
        save(userId, "MFA_DISABLED",
                viaRecoveryCode ? "MFA disabled using recovery code" : "MFA disabled using OTP code");
    }

    public void recordPasskeyRegistrationStarted(String userId) {
        save(userId, "PASSKEY_REGISTRATION_STARTED", "User initiated passkey registration");
    }

    public void recordPasskeyRegistered(String userId, String credentialId) {
        save(userId, "PASSKEY_REGISTERED",
                "New passkey registered (credential=" + abbreviate(credentialId) + ")");
    }

    public void recordPasskeyAuthenticationSuccess(String userId) {
        save(userId, "PASSKEY_AUTHENTICATION_SUCCESS", "User authenticated using passkey");
    }

    public void recordPasskeyAuthenticationFailure(String identifier) {
        save(null, "PASSKEY_AUTHENTICATION_FAILURE",
                "Failed passkey authentication for identifier=" + sanitize(identifier));
    }

    public void recordSessionsRevoked(String userId, int tokenVersion) {
        save(userId, "SESSIONS_REVOKED", "Token version bumped to " + tokenVersion);
    }

    private void save(String userId, String action, String details) {
        AuditLog log = AuditLog.builder()
                .userId(userId)
                .action(action)
                .targetType("AUTH")
                .details(details)
                .createdDate(Instant.now())
                .build();
        auditLogRepository.save(log);
    }

    private String sanitize(String identifier) {
        if (identifier == null) {
            return "unknown";
        }
        return identifier.replaceAll("[^a-zA-Z0-9@._-]", "?");
    }

    private String abbreviate(String credentialId) {
        if (credentialId == null) {
            return "unknown";
        }
        String trimmed = credentialId.trim();
        if (trimmed.length() <= 8) {
            return trimmed;
        }
        return trimmed.substring(0, 4) + "…" + trimmed.substring(trimmed.length() - 4);
    }
}