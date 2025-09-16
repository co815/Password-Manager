package com.example.pm.credential;

import com.example.pm.dto.CredentialDtos;
import com.example.pm.dto.CredentialDtos.GetAllCredentialResponse;
import com.example.pm.dto.CredentialDtos.PublicCredential;
import com.example.pm.model.Credential;
import com.example.pm.repo.CredentialRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import com.example.pm.exceptions.ErrorResponse;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController @RequestMapping("/api/credentials")
public class CredentialController {

    private final CredentialRepository credentials;

    public CredentialController(CredentialRepository credentials) {
        this.credentials = credentials;
    }

    @GetMapping
    public ResponseEntity<?> getAllCredentialsForUser(Authentication authentication) {

        String userID = (String) authentication.getPrincipal();

        List<PublicCredential> publicCredentialList = credentials.findByUserId(userID).stream()
                .map(PublicCredential::fromCredential)
                .toList();

        return ResponseEntity.ok(new GetAllCredentialResponse(publicCredentialList));

    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getCredentialById(Authentication authentication, @PathVariable String id) {

        String userId = (String) authentication.getPrincipal();

        return credentials.findById(id)
                .filter(c -> c.getUserId().equals(userId))  // ensure the credential belongs to the authenticated user
                .<ResponseEntity<?>>map(c -> ResponseEntity.ok(PublicCredential.fromCredential(c)))
                .orElseGet(() -> ResponseEntity.status(404)
                        .body(new ErrorResponse(404, "NOT FOUND", "Credential Not Found!")));

    }

    @PostMapping
    public ResponseEntity<?> addCredential(Authentication authentication, CredentialDtos.AddCredentialRequest addCredentialRequest) {

        String userID = (String) authentication.getPrincipal();

        if (credentials.findByService(addCredentialRequest.service()).isPresent()) {
            return ResponseEntity.status(404).body(new ErrorResponse(409,"CONFLICT","Credential for this service already exists"));
        }

        Credential newCredential = Credential.fromPostRequest(addCredentialRequest);
        credentials.save(newCredential);

        return ResponseEntity.ok().build();
    }

}