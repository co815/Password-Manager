package com.example.pm.repo;

import com.example.pm.model.Credential;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;

public interface CredentialRepository extends MongoRepository<Credential, String> {
    List<Credential> findByUserId(String userId);
}
