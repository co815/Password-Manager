package com.example.pm.repo;

import com.example.pm.model.VaultItem;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;
import java.util.Optional;

public interface VaultItemRepository extends MongoRepository<VaultItem, String> {
    List<VaultItem> findByUserId(String userId);

    Optional<VaultItem> findByIdAndUserId(String id, String userId);
}