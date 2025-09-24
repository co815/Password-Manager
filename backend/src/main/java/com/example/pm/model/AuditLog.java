package com.example.pm.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document("audit_logs")
public class AuditLog {
    @Id
    private String id;

    private String userId;
    private String action;
    private String targetType;
    private String targetId;
    private String details;

    @CreatedDate
    private Instant createdDate;
}
