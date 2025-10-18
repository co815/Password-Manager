package com.example.pm.repo;

import com.example.pm.auditlog.AuditLogQuery;
import com.example.pm.model.AuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public class AuditLogRepositoryCustomImpl implements AuditLogRepositoryCustom {

    private final MongoTemplate mongoTemplate;

    public AuditLogRepositoryCustomImpl(MongoTemplate mongoTemplate) {
        this.mongoTemplate = mongoTemplate;
    }

    @Override
    public Page<AuditLog> searchAuditLogs(AuditLogQuery query, Pageable pageable) {
        Query pagedQuery = buildQuery(query);
        if (pageable != null) {
            pagedQuery.with(pageable);
        }

        List<AuditLog> results = mongoTemplate.find(pagedQuery, AuditLog.class);
        Query countQuery = buildQuery(query);
        long total = mongoTemplate.count(countQuery, AuditLog.class);
        return new PageImpl<>(results, pageable, total);
    }

    private Query buildQuery(AuditLogQuery query) {
        Query mongoQuery = new Query();
        if (query == null) {
            return mongoQuery;
        }

        applyInCriteria(mongoQuery, "action", query.actions());
        applyInCriteria(mongoQuery, "targetType", query.targetTypes());

        if (query.targetId() != null && !query.targetId().isBlank()) {
            mongoQuery.addCriteria(Criteria.where("targetId").is(query.targetId()));
        }

        if (query.userId() != null && !query.userId().isBlank()) {
            mongoQuery.addCriteria(Criteria.where("userId").is(query.userId()));
        }

        if (query.from() != null || query.to() != null) {
            Criteria dateCriteria = Criteria.where("createdDate");
            if (query.from() != null) {
                dateCriteria = dateCriteria.gte(query.from());
            }
            if (query.to() != null) {
                dateCriteria = dateCriteria.lte(query.to());
            }
            mongoQuery.addCriteria(dateCriteria);
        }

        if (query.search() != null && !query.search().isBlank()) {
            String trimmed = query.search().trim();
            if (!trimmed.isEmpty()) {
                Pattern pattern = Pattern.compile(Pattern.quote(trimmed), Pattern.CASE_INSENSITIVE);
                List<Criteria> searchCriteria = new ArrayList<>();
                searchCriteria.add(Criteria.where("details").regex(pattern));
                searchCriteria.add(Criteria.where("action").regex(pattern));
                searchCriteria.add(Criteria.where("targetType").regex(pattern));
                searchCriteria.add(Criteria.where("targetId").regex(pattern));
                mongoQuery.addCriteria(new Criteria().orOperator(searchCriteria.toArray(new Criteria[0])));
            }
        }

        return mongoQuery;
    }

    private void applyInCriteria(Query query, String fieldName, Set<String> values) {
        if (values == null || values.isEmpty()) {
            return;
        }
        List<String> filtered = values.stream()
                .filter(value -> value != null && !value.isBlank())
                .toList();
        if (!filtered.isEmpty()) {
            query.addCriteria(Criteria.where(fieldName).in(filtered));
        }
    }
}
