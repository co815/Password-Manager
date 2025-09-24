package com.example.pm.auditlog;

import com.example.pm.config.AuditLogProps;
import com.example.pm.dto.AuditLogDtos;
import com.example.pm.exceptions.ErrorResponse;
import com.example.pm.model.AuditLog;
import com.example.pm.model.User;
import com.example.pm.repo.AuditLogRepository;
import com.example.pm.repo.UserRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

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
                                           @RequestParam(name = "limit", defaultValue = "100") int limit) {
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

        int pageSize = Math.max(1, Math.min(limit, 200));
        PageRequest pageRequest = PageRequest.of(0, pageSize, Sort.by(Sort.Direction.DESC, "createdDate"));
        List<AuditLog> logs = auditLogs.findAllByOrderByCreatedDateDesc(pageRequest).getContent();
        if (logs.isEmpty()) {
            return ResponseEntity.ok(new AuditLogDtos.ListResponse(Collections.emptyList()));
        }

        Set<String> actorIds = logs.stream()
                .map(AuditLog::getUserId)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());

        Map<String, User> actors = users.findAllById(actorIds).stream()
                .collect(Collectors.toMap(User::getId, Function.identity()));

        List<AuditLogDtos.AuditLogEntry> payload = logs.stream()
                .map(log -> {
                    User actor = actors.get(log.getUserId());
                    AuditLogDtos.Actor actorDto = AuditLogDtos.Actor.fromUser(actor);
                    return AuditLogDtos.AuditLogEntry.from(log, actorDto);
                })
                .toList();

        return ResponseEntity.ok(new AuditLogDtos.ListResponse(payload));
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