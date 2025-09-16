package com.example.pm.credential;

import com.example.pm.dto.CredentialDtos.GetAllCredentialResponse;
import com.example.pm.dto.CredentialDtos.PublicCredential;
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

    public CredentialController(CredentialRepository credentialRepository) {
        this.credentialRepository = credentialRepository;
    }

    @GetMapping
    public ResponseEntity<?> getAllCredentialsByUserId(Authentication authentication) {

        String userID = (String) authentication.getPrincipal();

        List<PublicCredential> publicCredentialList = credentialRepository.findByUserId(userID).stream()
                .map(PublicCredential::fromCredential)
                .toList();

        return ResponseEntity.ok(new GetAllCredentialResponse(publicCredentialList));

    }

    @GetMapping("/{service}")
    public ResponseEntity<?> getCredentialByUserId(Authentication authentication, @PathVariable String service) {

        String userID = (String) authentication.getPrincipal();

        return ResponseEntity.ok(new PublicCredential(credentialRepository.findByUserIdAndService(userID, service)))

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
