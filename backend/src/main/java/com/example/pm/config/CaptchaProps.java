package com.example.pm.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "app.auth.captcha")
public class CaptchaProps {

    public enum Provider {
        NONE,
        RECAPTCHA,
        HCAPTCHA
    }

    private Provider provider = Provider.NONE;
    private String siteKey;
    private String secretKey;
    private String verifyUrl;

    public Provider getProvider() {
        return provider;
    }

    public void setProvider(Provider provider) {
        this.provider = provider == null ? Provider.NONE : provider;
    }

    public String getSecretKey() {
        return secretKey;
    }

    public String getSiteKey() {
        return siteKey;
    }

    public void setSiteKey(String siteKey) {
        this.siteKey = siteKey;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public String getVerifyUrl() {
        if (verifyUrl != null && !verifyUrl.isBlank()) {
            return verifyUrl;
        }
        return switch (provider) {
            case RECAPTCHA -> "https://www.google.com/recaptcha/api/siteverify";
            case HCAPTCHA -> "https://hcaptcha.com/siteverify";
            case NONE -> "";
        };
    }

    public void setVerifyUrl(String verifyUrl) {
        this.verifyUrl = verifyUrl;
    }

    public boolean isEnabled() {
        return provider != Provider.NONE;
    }
}
