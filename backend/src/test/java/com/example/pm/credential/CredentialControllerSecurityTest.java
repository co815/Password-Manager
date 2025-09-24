package com.example.pm.credential;

import com.example.pm.dto.CredentialDtos;
import com.example.pm.model.Credential;
import com.example.pm.repo.AuditLogRepository;
import com.example.pm.repo.CredentialRepository;
import com.example.pm.security.JwtService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "app.jwt.secret=test_secret_key_with_more_than_32_chars!!",
        "server.ssl.enabled=false",
        "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.mongo.MongoAutoConfiguration,org.springframework.boot.autoconfigure.data.mongo.MongoDataAutoConfiguration"
})
@AutoConfigureMockMvc
class CredentialControllerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private CredentialRepository credentialRepository;

    @MockBean
    private AuditLogRepository auditLogRepository;

    @BeforeEach
    void setUp() {
        reset(credentialRepository);
    }

    @Test
    void getAllCredentialsWithoutTokenReturns401() throws Exception {
        mockMvc.perform(get("/api/credentials").secure(true))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void getAllCredentialsWithValidTokenReturnsData() throws Exception {
        var credential = new Credential();
        credential.setId("cred-1");
        credential.setUserId("user-123");
        credential.setService("Email");
        credential.setWebsiteLink("https://mail.example");
        credential.setUsernameEncrypted("usernameEnc");
        credential.setUsernameNonce("usernameNonce");
        credential.setPasswordEncrypted("passwordEnc");
        credential.setPasswordNonce("passwordNonce");

        when(credentialRepository.findByUserId("user-123"))
                .thenReturn(List.of(credential));

        String token = jwtService.generate("user-123");

        mockMvc.perform(get("/api/credentials")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .secure(true))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credentials[0].credentialId").value("cred-1"))
                .andExpect(jsonPath("$.credentials[0].service").value("Email"));
    }

    @Test
    void getCredentialByIdWithoutTokenReturns401() throws Exception {
        mockMvc.perform(get("/api/credentials/cred-1").secure(true))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void getCredentialByIdWithValidTokenReturnsData() throws Exception {
        var credential = new Credential();
        credential.setId("cred-1");
        credential.setUserId("user-123");
        credential.setService("Email");
        credential.setWebsiteLink("https://mail.example");
        credential.setUsernameEncrypted("usernameEnc");
        credential.setUsernameNonce("usernameNonce");
        credential.setPasswordEncrypted("passwordEnc");
        credential.setPasswordNonce("passwordNonce");

        when(credentialRepository.findById("cred-1"))
                .thenReturn(Optional.of(credential));

        String token = jwtService.generate("user-123");

        mockMvc.perform(get("/api/credentials/cred-1")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .secure(true))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credentialId").value("cred-1"))
                .andExpect(jsonPath("$.service").value("Email"));
    }

    @Test
    void addCredentialWithoutTokenReturns401() throws Exception {
        mockMvc.perform(post("/api/credentials")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}")
                        .secure(true))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void addCredentialWithValidTokenSavesCredential() throws Exception {
        when(credentialRepository.findByUserIdAndService("user-123", "Email"))
                .thenReturn(Optional.empty());
        when(credentialRepository.save(any(Credential.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        String token = jwtService.generate("user-123");

        mockMvc.perform(post("/api/credentials")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(createAddCredentialRequestJson(
                                "Email",
                                "https://mail.example",
                                "usernameEnc",
                                "usernameNonce",
                                "passwordEnc",
                                "passwordNonce"
                        ))
                        .secure(true))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.service").value("Email"))
                .andExpect(jsonPath("$.usernameEncrypted").value("usernameEnc"));

        verify(credentialRepository).save(argThat(saved ->
                "user-123".equals(saved.getUserId()) &&
                        "Email".equals(saved.getService())));
    }

    @Test
    void getAllCredentialsWhenRepositoryThrowsReturns500WithStatusPayload() throws Exception {
        when(credentialRepository.findByUserId("user-123"))
                .thenThrow(new RuntimeException("boom"));

        String token = jwtService.generate("user-123");

        mockMvc.perform(get("/api/credentials")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .secure(true))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.status").value(500));
    }

    @Test
    void addCredentialWithExistingServiceReturnsConflict() throws Exception {
        var credential = new Credential();
        credential.setId("cred-1");
        credential.setUserId("user-123");
        credential.setService("Email");

        when(credentialRepository.findByUserIdAndService("user-123", "Email"))
                .thenReturn(Optional.of(credential));

        String token = jwtService.generate("user-123");

        mockMvc.perform(post("/api/credentials")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(createAddCredentialRequestJson(
                                "Email",
                                "https://mail.example",
                                "usernameEnc",
                                "usernameNonce",
                                "passwordEnc",
                                "passwordNonce"
                        ))
                        .secure(true))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value("CONFLICT"))
                .andExpect(jsonPath("$.message")
                        .value("Credentials for this service already exist"));
    }

    @Test
    void updateCredentialWithoutTokenReturns401() throws Exception {
        mockMvc.perform(put("/api/credentials/cred-1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}")
                        .secure(true))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void updateCredentialWithValidTokenUpdatesData() throws Exception {
        var credential = new Credential();
        credential.setId("cred-1");
        credential.setUserId("user-123");
        credential.setService("Email");
        credential.setWebsiteLink("https://mail.example");
        credential.setUsernameEncrypted("usernameEnc");
        credential.setUsernameNonce("usernameNonce");
        credential.setPasswordEncrypted("passwordEnc");
        credential.setPasswordNonce("passwordNonce");

        when(credentialRepository.findById("cred-1"))
                .thenReturn(Optional.of(credential));
        when(credentialRepository.save(any(Credential.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        String token = jwtService.generate("user-123");

        mockMvc.perform(put("/api/credentials/cred-1")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{" +
                                "\"service\":\"New Service\"," +
                                "\"websiteLink\":\"https://new.example\"," +
                                "\"usernameEncrypted\":\"newUsernameEnc\"," +
                                "\"usernameNonce\":\"newUsernameNonce\"," +
                                "\"passwordEncrypted\":\"newPasswordEnc\"," +
                                "\"passwordNonce\":\"newPasswordNonce\"}")
                        .secure(true))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.service").value("New Service"))
                .andExpect(jsonPath("$.passwordEncrypted").value("newPasswordEnc"));

        verify(credentialRepository).save(argThat(saved ->
                "New Service".equals(saved.getService()) &&
                        "newPasswordEnc".equals(saved.getPasswordEncrypted())));
    }

    @Test
    void updateCredentialWithExistingServiceReturnsConflict() throws Exception {
        var credential = new Credential();
        credential.setId("cred-1");
        credential.setUserId("user-123");
        credential.setService("Bank");

        var conflictingCredential = new Credential();
        conflictingCredential.setId("cred-2");
        conflictingCredential.setUserId("user-123");
        conflictingCredential.setService("Email");

        when(credentialRepository.findById("cred-1"))
                .thenReturn(Optional.of(credential));
        when(credentialRepository.findByUserIdAndService("user-123", "Email"))
                .thenReturn(Optional.of(conflictingCredential));

        String token = jwtService.generate("user-123");

        mockMvc.perform(put("/api/credentials/cred-1")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{" +
                                "\"service\":\"Email\"}")
                        .secure(true))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409))
                .andExpect(jsonPath("$.type").value("CONFLICT"))
                .andExpect(jsonPath("$.message")
                        .value("Credentials for this service already exist"));

        verify(credentialRepository, never()).save(any(Credential.class));
    }

    @Test
    void updateCredentialWithPartialPayloadUpdatesOnlyProvidedFields() throws Exception {
        var credential = new Credential();
        credential.setId("cred-1");
        credential.setUserId("user-123");
        credential.setService("Email");
        credential.setWebsiteLink("https://mail.example");
        credential.setUsernameEncrypted("usernameEnc");
        credential.setUsernameNonce("usernameNonce");
        credential.setPasswordEncrypted("passwordEnc");
        credential.setPasswordNonce("passwordNonce");

        when(credentialRepository.findById("cred-1"))
                .thenReturn(Optional.of(credential));
        when(credentialRepository.save(any(Credential.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        String token = jwtService.generate("user-123");

        mockMvc.perform(put("/api/credentials/cred-1")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{" +
                                "\"passwordEncrypted\":\"newPasswordEnc\"," +
                                "\"passwordNonce\":\"newPasswordNonce\"}")
                        .secure(true))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.service").value("Email"))
                .andExpect(jsonPath("$.websiteLink").value("https://mail.example"))
                .andExpect(jsonPath("$.usernameEncrypted").value("usernameEnc"))
                .andExpect(jsonPath("$.passwordEncrypted").value("newPasswordEnc"))
                .andExpect(jsonPath("$.passwordNonce").value("newPasswordNonce"));

        verify(credentialRepository).save(argThat(saved ->
                "Email".equals(saved.getService()) &&
                        "https://mail.example".equals(saved.getWebsiteLink()) &&
                        "usernameEnc".equals(saved.getUsernameEncrypted()) &&
                        "usernameNonce".equals(saved.getUsernameNonce()) &&
                        "newPasswordEnc".equals(saved.getPasswordEncrypted()) &&
                        "newPasswordNonce".equals(saved.getPasswordNonce())));
    }

    @Test
    void updateCredentialWithBlankMandatoryFieldReturnsBadRequest() throws Exception {
        var credential = new Credential();
        credential.setId("cred-1");
        credential.setUserId("user-123");
        credential.setService("Email");

        when(credentialRepository.findById("cred-1"))
                .thenReturn(Optional.of(credential));

        String token = jwtService.generate("user-123");

        mockMvc.perform(put("/api/credentials/cred-1")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{" +
                                "\"service\":\"   \"}")
                        .secure(true))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.type").value("BAD_REQUEST"))
                .andExpect(jsonPath("$.message").value("Service must not be blank"));

        verify(credentialRepository, never()).save(any(Credential.class));
    }

    @Test
    void deleteCredentialWithoutTokenReturns401() throws Exception {
        mockMvc.perform(delete("/api/credentials/cred-1").secure(true))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void deleteCredentialWithValidTokenRemovesCredential() throws Exception {
        var credential = new Credential();
        credential.setId("cred-1");
        credential.setUserId("user-123");

        when(credentialRepository.findById("cred-1"))
                .thenReturn(Optional.of(credential));

        String token = jwtService.generate("user-123");

        mockMvc.perform(delete("/api/credentials/cred-1")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .secure(true))
                .andExpect(status().isNoContent());

        verify(credentialRepository).delete(argThat(saved -> "cred-1".equals(saved.getId())));
    }

    private String createAddCredentialRequestJson(String service,
                                                  String websiteLink,
                                                  String usernameEncrypted,
                                                  String usernameNonce,
                                                  String passwordEncrypted,
                                                  String passwordNonce) throws Exception {
        var request = new CredentialDtos.AddCredentialRequest(
                service,
                websiteLink,
                usernameEncrypted,
                usernameNonce,
                passwordEncrypted,
                passwordNonce
        );
        return objectMapper.writeValueAsString(request);
    }
}
