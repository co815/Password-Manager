package com.example.pm.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

@Component
@ConfigurationProperties(prefix = "app.auth.rate-limit")
public class RateLimitProps {

    private final List<String> trustedProxies = new ArrayList<>();

    public List<String> getTrustedProxies() {
        return Collections.unmodifiableList(trustedProxies);
    }

    public void setTrustedProxies(List<String> trustedProxies) {
        this.trustedProxies.clear();
        if (trustedProxies == null) {
            return;
        }
        for (String proxy : trustedProxies) {
            String normalized = normalize(proxy);
            if (!normalized.isEmpty()) {
                this.trustedProxies.add(normalized);
            }
        }
    }

    public boolean isTrustedProxy(String candidate) {
        if (candidate == null) {
            return false;
        }
        String normalized = normalize(candidate);
        return !normalized.isEmpty() && trustedProxies.contains(normalized);
    }

    private String normalize(String value) {
        if (value == null) {
            return "";
        }
        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            return "";
        }
        return trimmed.toLowerCase(Locale.ROOT);
    }
}