package com.example.pm.repo;

import com.example.pm.auditlog.AuditLogQuery;
import com.example.pm.model.AuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface AuditLogRepositoryCustom {
    Page<AuditLog> searchAuditLogs(AuditLogQuery query, Pageable pageable);
}
