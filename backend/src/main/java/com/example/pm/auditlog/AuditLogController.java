package com.example.pm.auditlog;

import com.example.pm.config.AuditLogProps;
import com.example.pm.dto.AuditLogDtos;
import com.example.pm.exceptions.ErrorResponse;
import com.example.pm.model.AuditLog;
import com.example.pm.model.User;
import com.example.pm.repo.AuditLogRepository;
import com.example.pm.repo.UserRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/audit-logs")
public class AuditLogController {

    private final AuditLogRepository auditLogs;
    private final UserRepository users;
    private final AuditLogProps auditLogProps;

    public AuditLogController(AuditLogRepository auditLogs,
                              UserRepository users,
                              AuditLogProps auditLogProps) {
        this.auditLogs = auditLogs;
        this.users = users;
        this.auditLogProps = auditLogProps;
    }

    @GetMapping
    public ResponseEntity<?> listAuditLogs(Authentication authentication,
                                           @RequestParam(name = "page", defaultValue = "0") int page,
                                           @RequestParam(name = "pageSize", defaultValue = "50") int pageSize,
                                           @RequestParam(name = "search", required = false) String search,
                                           @RequestParam(name = "action", required = false) List<String> actions,
                                           @RequestParam(name = "targetType", required = false) List<String> targetTypes,
                                           @RequestParam(name = "targetId", required = false) String targetId,
                                           @RequestParam(name = "actor", required = false) String actorIdentifier,
                                           @RequestParam(name = "from", required = false) String from,
                                           @RequestParam(name = "to", required = false) String to) {
        String userId = resolveUserId(authentication);
        if (userId == null) {
            return ResponseEntity.status(401)
                    .body(new ErrorResponse(401, "UNAUTHORIZED", "Invalid credentials"));
        }

        User currentUser = users.findById(userId).orElse(null);
        if (currentUser == null) {
            return ResponseEntity.status(401)
                    .body(new ErrorResponse(401, "UNAUTHORIZED", "User not found"));
        }

        if (!auditLogProps.isAdminEmail(currentUser.getEmail())) {
            return ResponseEntity.status(403)
                    .body(new ErrorResponse(403, "FORBIDDEN", "Audit log access is restricted"));
        }

        int safePage = Math.max(page, 0);
        int safePageSize = Math.max(1, Math.min(pageSize, 500));

        Instant fromInstant = parseInstant(from);
        Instant toInstant = parseInstant(to);

        String resolvedActorId = resolveActorIdentifier(actorIdentifier);
        if (actorIdentifier != null && !actorIdentifier.isBlank() && resolvedActorId == null) {
            return ResponseEntity.ok(new AuditLogDtos.ListResponse(
                    Collections.emptyList(),
                    safePage,
                    safePageSize,
                    0,
                    0,
                    false,
                    false
            ));
        }

        AuditLogQuery query = new AuditLogQuery(
                toNormalizedSet(actions),
                toNormalizedSet(targetTypes),
                normalize(targetId),
                resolvedActorId,
                normalize(search),
                fromInstant,
                toInstant
        );

        PageRequest pageRequest = PageRequest.of(safePage, safePageSize, Sort.by(Sort.Direction.DESC, "createdDate"));
        Page<AuditLog> pageResult = auditLogs.searchAuditLogs(query, pageRequest);
        List<AuditLog> logs = pageResult.getContent();
        if (logs.isEmpty()) {
            return ResponseEntity.ok(new AuditLogDtos.ListResponse(
                    Collections.emptyList(),
                    pageResult.getNumber(),
                    pageResult.getSize(),
                    pageResult.getTotalElements(),
                    pageResult.getTotalPages(),
                    pageResult.hasNext(),
                    pageResult.hasPrevious()
            ));
        }

        Set<String> actorIds = logs.stream()
                .map(AuditLog::getUserId)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());

        Map<String, User> actors = users.findAllById(actorIds).stream()
                .filter(user -> user.getId() != null && !user.getId().isBlank())
                .collect(Collectors.toMap(
                        User::getId,
                        Function.identity(),
                        (existing, duplicate) -> existing
                ));

        List<AuditLogDtos.AuditLogEntry> payload = logs.stream()
                .map(log -> {
                    User actor = actors.get(log.getUserId());
                    AuditLogDtos.Actor actorDto = AuditLogDtos.Actor.fromUser(actor);
                    return AuditLogDtos.AuditLogEntry.from(log, actorDto);
                })
                .toList();

        return ResponseEntity.ok(new AuditLogDtos.ListResponse(
                payload,
                pageResult.getNumber(),
                pageResult.getSize(),
                pageResult.getTotalElements(),
                pageResult.getTotalPages(),
                pageResult.hasNext(),
                pageResult.hasPrevious()
        ));
    }

    @GetMapping("/export")
    public ResponseEntity<?> exportAuditLogs(Authentication authentication,
                                             @RequestParam(name = "limit", defaultValue = "1000") int limit,
                                             @RequestParam(name = "search", required = false) String search,
                                             @RequestParam(name = "action", required = false) List<String> actions,
                                             @RequestParam(name = "targetType", required = false) List<String> targetTypes,
                                             @RequestParam(name = "targetId", required = false) String targetId,
                                             @RequestParam(name = "actor", required = false) String actorIdentifier,
                                             @RequestParam(name = "from", required = false) String from,
                                             @RequestParam(name = "to", required = false) String to,
                                             @RequestParam(name = "format", defaultValue = "csv") String format) {
        ResponseEntity<?> authResult = listAuditLogs(
                authentication,
                0,
                Math.max(1, Math.min(limit, 5000)),
                search,
                actions,
                targetTypes,
                targetId,
                actorIdentifier,
                from,
                to
        );

        if (!(authResult.getBody() instanceof AuditLogDtos.ListResponse response) || authResult.getStatusCode().value() != 200) {
            return authResult;
        }

        String normalizedFormat = normalizeExportFormat(format);
        if (normalizedFormat == null) {
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse(400, "INVALID_EXPORT_FORMAT", "Unsupported export format"));
        }

        if ("json".equals(normalizedFormat)) {
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_TYPE, "application/json")
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"audit-log-export.json\"")
                    .body(response.logs());
        }

        byte[] csvBytes = buildCsv(response.logs()).getBytes(StandardCharsets.UTF_8);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, "text/csv; charset=UTF-8")
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"audit-log-export.csv\"")
                .body(csvBytes);
    }

    private String normalizeExportFormat(String requestedFormat) {
        if (requestedFormat == null) {
            return "csv";
        }
        String normalized = requestedFormat.trim().toLowerCase();
        if (normalized.isEmpty()) {
            return "csv";
        }
        return switch (normalized) {
            case "csv", "json" -> normalized;
            default -> null;
        };
    }

    private Set<String> toNormalizedSet(List<String> values) {
        if (values == null || values.isEmpty()) {
            return Collections.emptySet();
        }
        return values.stream()
                .filter(value -> value != null && !value.isBlank())
                .map(String::trim)
                .collect(Collectors.toSet());
    }

    private Instant parseInstant(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(value.trim());
        } catch (DateTimeParseException ex) {
            return null;
        }
    }

    private String normalize(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private String resolveActorIdentifier(String actor) {
        if (actor == null || actor.isBlank()) {
            return null;
        }
        String normalized = actor.trim();
        if (users.findById(normalized).isPresent()) {
            return normalized;
        }
        return users.findByEmail(normalized)
                .or(() -> users.findByUsername(normalized))
                .map(User::getId)
                .orElse(null);
    }

    private String buildCsv(List<AuditLogDtos.AuditLogEntry> logs) {
        StringBuilder builder = new StringBuilder();
        builder.append("Timestamp,Actor Email,Actor Username,Actor Id,Action,Target Type,Target Id,Details\n");
        for (AuditLogDtos.AuditLogEntry entry : logs) {
            String actorEmail = entry.actor() != null ? coalesce(entry.actor().email()) : "";
            String actorUsername = entry.actor() != null ? coalesce(entry.actor().username()) : "";
            String actorId = entry.actor() != null ? coalesce(entry.actor().id()) : "";
            builder
                    .append(csvEscape(entry.createdDate() != null ? entry.createdDate().toString() : ""))
                    .append(',')
                    .append(csvEscape(actorEmail))
                    .append(',')
                    .append(csvEscape(actorUsername))
                    .append(',')
                    .append(csvEscape(actorId))
                    .append(',')
                    .append(csvEscape(coalesce(entry.action())))
                    .append(',')
                    .append(csvEscape(coalesce(entry.targetType())))
                    .append(',')
                    .append(csvEscape(coalesce(entry.targetId())))
                    .append(',')
                    .append(csvEscape(coalesce(entry.details())))
                    .append('\n');
        }
        return builder.toString();
    }

    private String coalesce(String value) {
        return value == null ? "" : value;
    }

    private String csvEscape(String value) {
        String escaped = value.replace("\"", "\"\"");
        if (escaped.contains(",") || escaped.contains("\n") || escaped.contains("\r") || escaped.contains("\"")) {
            return '"' + escaped + '"';
        }
        return escaped;
    }
    private String resolveUserId(Authentication authentication) {
        if (authentication == null) {
            return null;
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof String s && !s.isBlank()) {
            return s;
        }
        return null;
    }
}