package com.example.pm.credential;

import com.example.pm.dto.CredentialDtos;
import com.example.pm.model.Credential;
import com.example.pm.repo.CredentialRepository;
import com.example.pm.security.JwtService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController @RequestMapping("/api/credentials")
public class CredentialController {

    private final CredentialRepository credentialRepository;
    private final JwtService jwt;

    public CredentialController(CredentialRepository credentialRepository,  JwtService jwt) {
        this.credentialRepository = credentialRepository;
        this.jwt = jwt;
    }

    @GetMapping
    public ResponseEntity<?> getAllCredentialsByUserId(Authentication authentication) {

        String userID = (String) authentication.getPrincipal();
        List<Credential> credentials = credentialRepository.findByUserId(userID);

        return ResponseEntity.ok(new CredentialDtos.GetAllCredentialResponse(credentials));

    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getCredentialByUserId(Authentication authentication, @PathVariable String id) {

        String userID = (String) authentication.getPrincipal();

        return

    }

    @PostMapping
    public ResponseEntity<?> addCredential(CredentialDtos.RegisterCredentialRequest registerRequest) {
        return ResponseEntity.ok(credentialRepository.save(new Credential(registerRequest)));
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> updateCredential(CredentialDtos.ModifyCredentialRequest modifyRequest) {
        return  ResponseEntity.ok();
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteCredential(CredentialDtos.DeleteCredentialRequest deleteRequest) {

    }

}
