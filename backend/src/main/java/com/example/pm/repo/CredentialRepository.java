package com.example.pm.repo;

import com.example.pm.model.Credential;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;
import java.util.Optional;

public interface CredentialRepository extends MongoRepository<Credential, String> {
    List<Credential> findByUserId(String userId);
    Optional<Credential> findByUserIdAndService(String userId, String service);
    Optional<Credential> findByUserIdAndServiceIgnoreCase(String userId, String service);
    Optional<Credential> findByService(String service);
}
