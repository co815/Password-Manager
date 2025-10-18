package com.example.pm.auditlog;

import java.time.Instant;
import java.util.Collections;
import java.util.Set;

public record AuditLogQuery(
        Set<String> actions,
        Set<String> targetTypes,
        String targetId,
        String userId,
        String search,
        Instant from,
        Instant to
) {
    public AuditLogQuery {
        actions = actions == null ? Collections.emptySet() : actions;
        targetTypes = targetTypes == null ? Collections.emptySet() : targetTypes;
    }
}
