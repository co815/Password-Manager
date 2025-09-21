package com.example.pm.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

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
    }

    private SameSiteMode sameSite = SameSiteMode.STRICT;

    public SameSiteMode getSameSite() {
        return sameSite;
    }

    public void setSameSite(SameSiteMode sameSite) {
        this.sameSite = sameSite != null ? sameSite : SameSiteMode.STRICT;
    }

    public String getSameSiteAttribute() {
        return sameSite.getAttributeValue();
    }
}