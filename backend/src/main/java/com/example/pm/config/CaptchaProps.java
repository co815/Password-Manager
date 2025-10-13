package com.example.pm.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.concurrent.atomic.AtomicBoolean;

@Component
@ConfigurationProperties(prefix = "app.auth.captcha")
public class CaptchaProps {

    public enum Provider {
        NONE,
        RECAPTCHA
    }

    private static final Logger log = LoggerFactory.getLogger(CaptchaProps.class);

    private Provider provider = Provider.NONE;
    private String siteKey;
    private String secretKey;
    private String verifyUrl;

    private final AtomicBoolean siteKeyWarned = new AtomicBoolean(false);
    private final AtomicBoolean secretKeyWarned = new AtomicBoolean(false);

    public Provider getProvider() {
        return provider;
    }

    public void setProvider(Provider provider) {
        this.provider = provider == null ? Provider.NONE : provider;
    }

    public String getSiteKey() {
        return resolveSiteKey();
    }

    public void setSiteKey(String siteKey) {
        this.siteKey = siteKey;
    }

    public String getSecretKey() {
        return resolveSecretKey();
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public String getVerifyUrl() {
        if (verifyUrl != null && !verifyUrl.isBlank()) {
            return verifyUrl;
        }
        return provider == Provider.RECAPTCHA
                ? "https://www.google.com/recaptcha/api/siteverify"
                : "";
    }

    public void setVerifyUrl(String verifyUrl) {
        this.verifyUrl = verifyUrl;
    }

    public boolean isEnabled() {
        return provider != Provider.NONE;
    }

    private String resolveSiteKey() {
        String configured = siteKey;
        if (configured != null && !configured.isBlank()) {
            return configured.trim();
        }

        String envKey = provider == Provider.RECAPTCHA ? env("RECAPTCHA_SITE_KEY") : null;

        if (envKey != null && !envKey.isBlank()) {
            return envKey.trim();
        }

        if (provider == Provider.RECAPTCHA && siteKeyWarned.compareAndSet(false, true)) {
            log.warn("Captcha provider {} is enabled but no site key was found. Set the RECAPTCHA_SITE_KEY environment variable or app.auth.captcha.site-key property.",
                    provider);
        }

        return null;
    }

    private String resolveSecretKey() {
        String configured = secretKey;
        if (configured != null && !configured.isBlank()) {
            return configured.trim();
        }

        String envKey = provider == Provider.RECAPTCHA ? env("RECAPTCHA_SECRET_KEY") : null;

        if (envKey != null && !envKey.isBlank()) {
            return envKey.trim();
        }

        if (provider == Provider.RECAPTCHA && secretKeyWarned.compareAndSet(false, true)) {
            log.warn("Captcha provider {} is enabled but no secret key was found. Set the RECAPTCHA_SECRET_KEY environment variable or app.auth.captcha.secret-key property.",
                    provider);
        }

        return null;
    }

    private String env(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }
}
