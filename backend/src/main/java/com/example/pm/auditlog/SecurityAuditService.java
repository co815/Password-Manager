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
}