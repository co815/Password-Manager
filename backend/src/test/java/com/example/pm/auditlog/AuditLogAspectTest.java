package com.example.pm.auditlog;

import com.example.pm.model.AuditLog;
import com.example.pm.repo.AuditLogRepository;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.Signature;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuditLogAspectTest {

    private AuditLogRepository auditLogRepository;
    private AuditLogAspect aspect;

    @BeforeEach
    void setUp() {
        auditLogRepository = mock(AuditLogRepository.class);
        aspect = new AuditLogAspect(auditLogRepository);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void detailsAreSummarizedWithoutSensitiveData() {
        SecurityContextHolder.getContext()
                .setAuthentication(new UsernamePasswordAuthenticationToken("user-123", null));

        JoinPoint joinPoint = mock(JoinPoint.class);
        Signature signature = mock(Signature.class);
        when(signature.getName()).thenReturn("create");
        when(signature.toShortString()).thenReturn("create");
        when(signature.toLongString()).thenReturn("create");
        when(signature.getDeclaringType()).thenReturn(DummyController.class);
        when(signature.getDeclaringTypeName()).thenReturn(DummyController.class.getName());
        when(joinPoint.getSignature()).thenReturn(signature);
        when(joinPoint.getTarget()).thenReturn(new DummyController());
        when(joinPoint.getArgs()).thenReturn(new Object[]{
                "super-secret",
                new TestPayload("hidden-value")
        });

        ResponseEntity<TestPayload> result = ResponseEntity.ok(new TestPayload("response-secret"));
        aspect.saveAuditLog(joinPoint, result);

        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogRepository).save(captor.capture());

        AuditLog auditLog = captor.getValue();
        assertThat(auditLog.getDetails()).contains("String(len=");
        assertThat(auditLog.getDetails()).contains("ResponseEntity");
        assertThat(auditLog.getDetails()).doesNotContain("super-secret");
        assertThat(auditLog.getDetails()).doesNotContain("hidden-value");
        assertThat(auditLog.getDetails()).doesNotContain("response-secret");
    }

    private static class DummyController { }

    private record TestPayload(String value) { }
}