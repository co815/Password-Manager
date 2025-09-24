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

import java.time.Instant;

@Aspect
@Component
@RequiredArgsConstructor
public class AuditLogAspect {

    private final AuditLogRepository auditLogRepo;

    // Pointcut for all public methods in your controllers
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
                .details(result != null ? result.toString() : null)
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
}
