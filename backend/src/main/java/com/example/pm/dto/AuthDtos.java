package com.example.pm.dto;

import com.example.pm.config.CaptchaProps;
import com.example.pm.model.User;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class AuthDtos {

    public record PublicUser(
            String id,
            String email,
            String username,
            String saltClient,
            String dekEncrypted,
            String dekNonce,
            String avatarData,
            boolean mfaEnabled,
            java.time.Instant masterPasswordLastRotated,
            java.time.Instant mfaEnabledAt,
            boolean emailVerified
    ) {
        public static PublicUser fromUser(User user) {
            return new PublicUser(
                    user.getId(),
                    user.getEmail(),
                    user.getUsername(),
                    user.getSaltClient(),
                    user.getDekEncrypted(),
                    user.getDekNonce(),
                    user.getAvatarData(),
                    user.isMfaEnabled(),
                    user.getMasterPasswordLastRotated(),
                    user.getMfaEnabledAt(),
                    user.isEmailVerified()
            );
        }
    }

    public record RegisterRequest(
            @Email String email,
            @NotBlank @Size(min = 4, max = 64) String username,
            @NotBlank String verifier,
            @NotBlank String saltClient,
            @NotBlank String dekEncrypted,
            @NotBlank String dekNonce,
            String avatarData,
            String captchaToken
    ) {}

    public record LoginRequest(
            @Email String email,
            @NotBlank String verifier,
            String mfaCode,
            String recoveryCode,
            String captchaToken
    ) {}

    public record LoginResponse(
            PublicUser user
    ) {}

    public record SaltResponse(
            String email,
            String saltClient
    ) {}

    public record AvatarUploadRequest(
            String avatarData
    ) {}

    public record RotateMasterPasswordRequest(
            @NotBlank String currentVerifier,
            @NotBlank String newVerifier,
            @NotBlank String newSaltClient,
            @NotBlank String newDekEncrypted,
            @NotBlank String newDekNonce,
            boolean invalidateSessions
    ) {}

    public record RotateMasterPasswordResponse(
            java.time.Instant rotatedAt,
            boolean sessionsInvalidated
    ) {}

    public record ResetMasterPasswordRequest(
            @Email String email,
            @NotBlank String recoveryCode,
            @NotBlank String newVerifier,
            @NotBlank String newSaltClient,
            @NotBlank String newDekEncrypted,
            @NotBlank String newDekNonce,
            boolean disableMfa
    ) {}

    public record SimpleMessageResponse(String message) {}

    public record ResendVerificationRequest(
            @NotBlank @Email String email
    ) {}

    public record MfaEnrollmentResponse(
            String secret,
            String otpauthUrl,
            java.util.List<String> recoveryCodes
    ) {}

    public record MfaStatusResponse(
            boolean enabled,
            java.time.Instant enabledAt,
            int recoveryCodesRemaining
    ) {}

    public record MfaActivationRequest(
            @NotBlank String code
    ) {}

    public record MfaDisableRequest(
            String code,
            String recoveryCode
    ) {}

    public record RevokeSessionsResponse(int tokenVersion) {}

    public record CaptchaConfigResponse(
            boolean enabled,
            CaptchaProps.Provider provider,
            String siteKey
    ) {}
}
