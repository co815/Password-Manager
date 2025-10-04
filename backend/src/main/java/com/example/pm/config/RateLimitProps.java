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
    private final Login login = new Login();

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

    public Login getLogin() {
        return login;
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

    public static class Login {

        private int perMinute = 10;
        private int perHour = 50;

        public int getPerMinute() {
            return perMinute;
        }

        public void setPerMinute(int perMinute) {
            this.perMinute = Math.max(1, perMinute);
        }

        public int getPerHour() {
            return perHour;
        }

        public void setPerHour(int perHour) {
            this.perHour = Math.max(1, perHour);
        }
    }
}