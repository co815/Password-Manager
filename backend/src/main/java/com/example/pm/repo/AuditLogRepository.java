package com.example.pm.repo;

import com.example.pm.model.AuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface AuditLogRepository extends MongoRepository<AuditLog,String> {
    Page<AuditLog> findAllByOrderByCreatedDateDesc(Pageable pageable);
}
