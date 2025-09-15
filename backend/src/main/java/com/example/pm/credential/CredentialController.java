package com.example.pm.credential;

import com.example.pm.repo.CredentialRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController @RequestMapping("/api/credentials")
public class CredentialController {

    private final CredentialRepository credentialRepository;

    public CredentialController(CredentialRepository credentialRepository) {
        this.credentialRepository = credentialRepository;
    }

    @GetMapping
    public ResponseEntity<?> getAllCredentialsByUserId(@RequestParam String userId) {
        return ResponseEntity.ok(credentialRepository.findAll());
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getCredentialByUserId(@RequestParam String userId) {
        return ResponseEntity.ok(credentialRepository.findById(userId));
    }

}
