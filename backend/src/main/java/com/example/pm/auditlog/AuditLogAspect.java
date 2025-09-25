package com.example.pm.auditlog;

import com.example.pm.model.AuditLog;
import com.example.pm.repo.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import org.springframework.http.ResponseEntity;

import java.lang.reflect.Array;
import java.time.Instant;
import java.util.Collection;
import java.util.Map;
import java.util.StringJoiner;

@Aspect
@Component
@RequiredArgsConstructor
public class AuditLogAspect {

    private final AuditLogRepository auditLogRepo;

    @Pointcut("execution(public * com.example.pm.*.*Controller.*(..))")
    public void controllerMethods() {}

    @AfterReturning(pointcut = "controllerMethods()", returning = "result")
    public void saveAuditLog(JoinPoint joinPoint, Object result) {
        String userId = resolveUserId();
        if (userId == null) return;

        String action = joinPoint.getSignature().getName().toUpperCase();
        String targetType = joinPoint.getTarget().getClass().getSimpleName();
        String targetId = extractTargetId(joinPoint);

        AuditLog auditLog = AuditLog.builder()
                .userId(userId)
                .action(action)
                .targetType(targetType)
                .targetId(targetId)
                .details(resolveDetails(joinPoint, result))
                .createdDate(Instant.now())
                .build();

        saveAuditLogAsync(auditLog);
    }

    @Async
    public void saveAuditLogAsync(AuditLog auditLog) {
        auditLogRepo.save(auditLog);
    }

    private String resolveUserId() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof String s) {
            return s;
        }
        return null;
    }

    private String extractTargetId(JoinPoint joinPoint) {
        for (Object arg : joinPoint.getArgs()) {
            if (arg instanceof String s && !s.isEmpty()) {
                return s;
            }
        }
        return null;
    }

    private String resolveDetails(JoinPoint joinPoint, Object result) {
        if (isAuditLogListing(joinPoint)) {
            return formatAuditLogListingDetails(joinPoint, result);
        }
        return String.format("Invoked %s.%s %s -> %s",
                joinPoint.getTarget().getClass().getSimpleName(),
                joinPoint.getSignature().getName(),
                summarizeArguments(joinPoint.getArgs()),
                summarizeResult(result));
    }

    private boolean isAuditLogListing(JoinPoint joinPoint) {
        return "LISTAUDITLOGS".equalsIgnoreCase(joinPoint.getSignature().getName())
                && "AuditLogController".equals(joinPoint.getTarget().getClass().getSimpleName());
    }

    private String formatAuditLogListingDetails(JoinPoint joinPoint, Object result) {
        Integer limit = null;
        for (Object arg : joinPoint.getArgs()) {
            if (arg instanceof Integer intArg) {
                limit = intArg;
                break;
            }
        }
        String base = "Viewed audit log entries";
        if (limit != null) {
            base = base + " (limit=" + limit + ")";
        }
        return String.format("%s -> %s", base, summarizeResult(result));
    }

    private String summarizeArguments(Object[] args) {
        if (args == null || args.length == 0) {
            return "args=[]";
        }

        StringJoiner joiner = new StringJoiner(", ", "args=[", "]");
        for (Object arg : args) {
            joiner.add(summarizeArgument(arg));
        }
        return joiner.toString();
    }

    private String summarizeArgument(Object arg) {
        if (arg == null) {
            return "null";
        }
        if (arg instanceof String s) {
            return "String(len=" + s.length() + ")";
        }
        if (arg instanceof Number || arg instanceof Enum<?>) {
            return arg.getClass().getSimpleName();
        }
        if (arg instanceof Collection<?> collection) {
            return collection.getClass().getSimpleName() + "(size=" + collection.size() + ")";
        }
        if (arg instanceof Map<?, ?> map) {
            return map.getClass().getSimpleName() + "(size=" + map.size() + ")";
        }
        if (arg.getClass().isArray()) {
            return "Array(type=" + arg.getClass().getComponentType().getSimpleName()
                    + ",len=" + Array.getLength(arg) + ")";
        }
        return arg.getClass().getSimpleName();
    }

    private String summarizeResult(Object result) {
        if (result == null) {
            return "result=null";
        }
        if (result instanceof ResponseEntity<?> response) {
            return "result=ResponseEntity(status=" + response.getStatusCode()
                    + ",body=" + summarizeBody(response.getBody()) + ")";
        }
        if (result instanceof Collection<?> collection) {
            return "result=" + collection.getClass().getSimpleName()
                    + "(size=" + collection.size() + ")";
        }
        if (result instanceof Map<?, ?> map) {
            return "result=" + map.getClass().getSimpleName()
                    + "(size=" + map.size() + ")";
        }
        if (result.getClass().isArray()) {
            return "result=Array(type=" + result.getClass().getComponentType().getSimpleName()
                    + ",len=" + Array.getLength(result) + ")";
        }
        return "result=" + result.getClass().getSimpleName();
    }

    private String summarizeBody(Object body) {
        if (body == null) {
            return "null";
        }
        if (body instanceof Collection<?> collection) {
            return collection.getClass().getSimpleName() + "(size=" + collection.size() + ")";
        }
        if (body instanceof Map<?, ?> map) {
            return map.getClass().getSimpleName() + "(size=" + map.size() + ")";
        }
        if (body.getClass().isArray()) {
            return "Array(type=" + body.getClass().getComponentType().getSimpleName()
                    + ",len=" + Array.getLength(body) + ")";
        }
        return body.getClass().getSimpleName();
    }
}
