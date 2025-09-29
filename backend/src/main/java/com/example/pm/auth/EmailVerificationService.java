package com.example.pm.auth;

import com.example.pm.config.EmailVerificationProps;
import com.example.pm.model.User;
import com.example.pm.repo.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;

@Service
public class EmailVerificationService {

    private static final Logger log = LoggerFactory.getLogger(EmailVerificationService.class);

    private final UserRepository userRepository;
    private final EmailVerificationProps props;
    private final EmailSender emailSender;
    private final SecureRandom secureRandom = new SecureRandom();
    private final Clock clock;

    public enum VerificationResult {
        VERIFIED,
        INVALID_TOKEN,
        EXPIRED
    }

    public enum ResendResult {
        SENT,
        USER_NOT_FOUND,
        ALREADY_VERIFIED,
        RATE_LIMITED
    }

    @Autowired
    public EmailVerificationService(UserRepository userRepository,
                                    EmailVerificationProps props,
                                    EmailSender emailSender) {
        this(userRepository, props, emailSender, Clock.systemUTC());
    }

    EmailVerificationService(UserRepository userRepository,
                             EmailVerificationProps props,
                             EmailSender emailSender,
                             Clock clock) {
        this.userRepository = userRepository;
        this.props = props;
        this.emailSender = emailSender;
        this.clock = clock;
    }

    public User registerPendingUser(User user) {
        return sendVerification(user);
    }

    public ResendResult resendVerification(String email) {
        if (!StringUtils.hasText(email)) {
            return ResendResult.USER_NOT_FOUND;
        }
        String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);
        return userRepository.findByEmail(normalizedEmail)
                .map(user -> {
                    if (user.isEmailVerified()) {
                        return ResendResult.ALREADY_VERIFIED;
                    }
                    if (!canResend(user)) {
                        return ResendResult.RATE_LIMITED;
                    }
                    sendVerification(user);
                    return ResendResult.SENT;
                })
                .orElse(ResendResult.USER_NOT_FOUND);
    }

    public VerificationResult verifyToken(String token) {
        if (!StringUtils.hasText(token)) {
            return VerificationResult.INVALID_TOKEN;
        }
        String normalizedToken = token.trim();
        String hashedToken = hashToken(normalizedToken);
        return userRepository.findByEmailVerificationToken(hashedToken)
                .map(user -> {
                    if (isTokenExpired(user)) {
                        return VerificationResult.EXPIRED;
                    }
                    user.setEmailVerified(true);
                    user.setEmailVerificationToken(null);
                    user.setEmailVerificationSentAt(null);
                    userRepository.save(user);
                    return VerificationResult.VERIFIED;
                })
                .orElse(VerificationResult.INVALID_TOKEN);
    }

    private User sendVerification(User user) {
        String rawToken = generateToken();
        user.setEmailVerified(false);
        user.setEmailVerificationToken(hashToken(rawToken));
        user.setEmailVerificationSentAt(Instant.now(clock));
        User saved = userRepository.save(user);
        String link = buildVerificationLink(rawToken);
        try {
            emailSender.sendVerificationEmail(saved.getEmail(), saved.getUsername(), link);
        } catch (Exception ex) {
            log.error("Failed to send verification email to {}", saved.getEmail(), ex);
        }
        return saved;
    }

    private String buildVerificationLink(String token) {
        String baseUrl = props.getVerificationBaseUrl();
        if (!StringUtils.hasText(baseUrl)) {
            return token;
        }
        String trimmed = baseUrl.trim();
        if (trimmed.endsWith("=") || trimmed.endsWith("/")) {
            return trimmed + token;
        }
        if (trimmed.contains("?")) {
            return trimmed + token;
        }
        if (trimmed.endsWith("token")) {
            return trimmed + "=" + token;
        }
        return trimmed + "?token=" + token;
    }

    private boolean canResend(User user) {
        Instant sentAt = user.getEmailVerificationSentAt();
        if (sentAt == null) {
            return true;
        }
        Duration cooldown = props.getResendCooldown();
        if (cooldown == null || cooldown.isNegative() || cooldown.isZero()) {
            return true;
        }
        Instant now = Instant.now(clock);
        return sentAt.plus(cooldown).isBefore(now) || sentAt.plus(cooldown).equals(now);
    }

    private boolean isTokenExpired(User user) {
        Instant sentAt = user.getEmailVerificationSentAt();
        if (sentAt == null) {
            return true;
        }
        Duration ttl = props.getTokenTtl();
        if (ttl == null || ttl.isNegative() || ttl.isZero()) {
            return false;
        }
        Instant now = Instant.now(clock);
        return sentAt.plus(ttl).isBefore(now);
    }

    private String generateToken() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hashed);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
