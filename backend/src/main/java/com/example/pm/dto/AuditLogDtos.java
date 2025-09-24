package com.example.pm.dto;

import com.example.pm.model.AuditLog;
import com.example.pm.model.User;

import java.time.Instant;
import java.util.List;

public class AuditLogDtos {

    public record Actor(
            String id,
            String email,
            String username
    ) {
        public static Actor fromUser(User user) {
            if (user == null) {
                return null;
            }
            return new Actor(user.getId(), user.getEmail(), user.getUsername());
        }
    }

    public record AuditLogEntry(
            String id,
            Instant createdDate,
            String action,
            String targetType,
            String targetId,
            String details,
            Actor actor
    ) {
        public static AuditLogEntry from(AuditLog log, Actor actor) {
            if (log == null) {
                return null;
            }
            return new AuditLogEntry(
                    log.getId(),
                    log.getCreatedDate(),
                    log.getAction(),
                    log.getTargetType(),
                    log.getTargetId(),
                    log.getDetails(),
                    actor
            );
        }
    }

    public record ListResponse(
            List<AuditLogEntry> logs
    ) {}
}