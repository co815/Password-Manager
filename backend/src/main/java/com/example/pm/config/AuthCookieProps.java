package com.example.pm.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.Arrays;

@Component
@ConfigurationProperties(prefix = "app.auth.cookie")
public class AuthCookieProps {

    public enum SameSiteMode {
        STRICT("Strict"),
        LAX("Lax"),
        NONE("None");

        private final String attributeValue;

        SameSiteMode(String attributeValue) {
            this.attributeValue = attributeValue;
        }

        public String getAttributeValue() {
            return attributeValue;
        }

        public static SameSiteMode from(String value) {
            if (value == null) {
                return STRICT;
            }

            String candidate = value.trim();
            if (candidate.isEmpty()) {
                return STRICT;
            }

            return Arrays.stream(values())
                    .filter(mode -> mode.name().equalsIgnoreCase(candidate)
                            || mode.attributeValue.equalsIgnoreCase(candidate))
                    .findFirst()
                    .orElseThrow(() -> new IllegalArgumentException("Unknown SameSite mode: " + value));
        }

        public static SameSiteMode from(String value) {
            if (value == null) {
                return STRICT;
            }

            String candidate = value.trim();
            if (candidate.isEmpty()) {
                return STRICT;
            }

            return Arrays.stream(values())
                    .filter(mode -> mode.name().equalsIgnoreCase(candidate)
                            || mode.attributeValue.equalsIgnoreCase(candidate))
                    .findFirst()
                    .orElseThrow(() -> new IllegalArgumentException("Unknown SameSite mode: " + value));
        }
    }

    private SameSiteMode sameSite = SameSiteMode.STRICT;

    public SameSiteMode getSameSite() {
        return sameSite;
    }

    public void setSameSite(SameSiteMode sameSite) {
        this.sameSite = sameSite != null ? sameSite : SameSiteMode.STRICT;
    }

    public void setSameSite(String sameSite) {
        this.sameSite = SameSiteMode.from(sameSite);
    }

    public String getSameSiteAttribute() {
        return sameSite.getAttributeValue();
    }
}