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
        RECAPTCHA,
        HCAPTCHA,
        TURNSTILE,
        GENERIC
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
        return switch (provider) {
            case RECAPTCHA -> "https://www.google.com/recaptcha/api/siteverify";
            case HCAPTCHA -> "https://hcaptcha.com/siteverify";
            case TURNSTILE -> "https://challenges.cloudflare.com/turnstile/v0/siteverify";
            case GENERIC, NONE -> "";
        };
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

        String envKey = switch (provider) {
            case RECAPTCHA -> env("RECAPTCHA_SITE_KEY");
            case TURNSTILE -> env("TURNSTILE_SITE_KEY");
            case HCAPTCHA -> env("HCAPTCHA_SITE_KEY");
            case GENERIC, NONE -> null;
        };

        if (envKey != null && !envKey.isBlank()) {
            return envKey.trim();
        }

        if (requiresExternalKey(provider) && siteKeyWarned.compareAndSet(false, true)) {
            log.warn("Captcha provider {} is enabled but no site key was found. Set the {} environment variable or app.auth.captcha.site-key property.",
                    provider,
                    provider == Provider.TURNSTILE ? "TURNSTILE_SITE_KEY" : provider == Provider.RECAPTCHA
                            ? "RECAPTCHA_SITE_KEY" : "HCAPTCHA_SITE_KEY");
        }

        return null;
    }

    private String resolveSecretKey() {
        String configured = secretKey;
        if (configured != null && !configured.isBlank()) {
            return configured.trim();
        }

        String envKey = switch (provider) {
            case RECAPTCHA -> env("RECAPTCHA_SECRET_KEY");
            case TURNSTILE -> env("TURNSTILE_SECRET_KEY");
            case HCAPTCHA -> env("HCAPTCHA_SECRET_KEY");
            case GENERIC, NONE -> null;
        };

        if (envKey != null && !envKey.isBlank()) {
            return envKey.trim();
        }

        if (requiresExternalKey(provider) && secretKeyWarned.compareAndSet(false, true)) {
            log.warn("Captcha provider {} is enabled but no secret key was found. Set the {} environment variable or app.auth.captcha.secret-key property.",
                    provider,
                    provider == Provider.TURNSTILE ? "TURNSTILE_SECRET_KEY" : provider == Provider.RECAPTCHA
                            ? "RECAPTCHA_SECRET_KEY" : "HCAPTCHA_SECRET_KEY");
        }

        return null;
    }

    private boolean requiresExternalKey(Provider provider) {
        return provider == Provider.RECAPTCHA || provider == Provider.HCAPTCHA || provider == Provider.TURNSTILE;
    }

    private String env(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }
}
