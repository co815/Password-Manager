package com.example.pm.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
@ConfigurationProperties(prefix = "app.auth.email-verification")
public class EmailVerificationProps {

    private String verificationBaseUrl = "http://localhost:3000/verify-email";
    private Duration tokenTtl = Duration.ofHours(24);
    private Duration resendCooldown = Duration.ofMinutes(5);

    public String getVerificationBaseUrl() {
        return verificationBaseUrl;
    }

    public void setVerificationBaseUrl(String verificationBaseUrl) {
        this.verificationBaseUrl = verificationBaseUrl;
    }

    public Duration getTokenTtl() {
        return tokenTtl;
    }

    public void setTokenTtl(Duration tokenTtl) {
        this.tokenTtl = tokenTtl != null ? tokenTtl : Duration.ofHours(24);
    }

    public Duration getResendCooldown() {
        return resendCooldown;
    }

    public void setResendCooldown(Duration resendCooldown) {
        this.resendCooldown = resendCooldown != null ? resendCooldown : Duration.ofMinutes(5);
    }
}