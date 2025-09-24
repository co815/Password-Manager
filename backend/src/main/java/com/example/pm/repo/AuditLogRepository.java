package com.example.pm.repo;

import com.example.pm.model.AuditLog;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;

public interface AuditLogRepository extends MongoRepository<AuditLog,String> {
    // List<AuditLog> findByUserId(String userId);
}
