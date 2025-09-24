package com.example.pm.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@Component
@ConfigurationProperties(prefix = "app.audit")
public class AuditLogProps {

    private List<String> adminEmails = new ArrayList<>();

    public List<String> getAdminEmails() {
        return new ArrayList<>(adminEmails);
    }

    public void setAdminEmails(List<String> adminEmails) {
        if (adminEmails == null) {
            this.adminEmails = new ArrayList<>();
            return;
        }

        Set<String> normalized = new LinkedHashSet<>();
        for (String email : adminEmails) {
            if (email == null) {
                continue;
            }
            String trimmed = email.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            normalized.add(trimmed.toLowerCase(Locale.ROOT));
        }
        this.adminEmails = new ArrayList<>(normalized);
    }

    public boolean isAdminEmail(String email) {
        if (email == null) {
            return false;
        }
        String normalized = email.trim().toLowerCase(Locale.ROOT);
        if (normalized.isEmpty()) {
            return false;
        }
        return adminEmails.contains(normalized);
    }
}