package com.example.pm.vault;

import com.example.pm.auditlog.AuditLogAspect;
import com.example.pm.auditlog.AuditLogController;
import com.example.pm.model.VaultItem;
import com.example.pm.repo.VaultItemRepository;
import com.example.pm.security.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
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
class VaultControllerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtService jwtService;

    @MockBean
    private VaultItemRepository vaultItemRepository;

    @MockBean
    private AuditLogController auditLogController;

    @MockBean
    private AuditLogAspect auditLogAspect;

    @BeforeEach
    void setUp() {
        reset(vaultItemRepository);
    }

    @Test
    void listVaultWithoutTokenReturns401() throws Exception {
        mockMvc.perform(get("/api/vault").secure(true))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void listVaultWithTokenReturnsItems() throws Exception {
        VaultItem item = new VaultItem();
        item.setId("item-1");
        item.setUserId("user-123");
        item.setTitleCipher("titleCipher");
        item.setTitleNonce("titleNonce");
        item.setUsernameCipher("usernameCipher");
        item.setUsernameNonce("usernameNonce");
        item.setPasswordCipher("passwordCipher");
        item.setPasswordNonce("passwordNonce");
        item.setUrl("https://example.com");
        item.setNotesCipher("notesCipher");
        item.setNotesNonce("notesNonce");
        item.setCreatedAt(Instant.parse("2024-01-01T00:00:00Z"));
        item.setUpdatedAt(Instant.parse("2024-01-01T00:00:00Z"));

        when(vaultItemRepository.findByUserId("user-123"))
                .thenReturn(List.of(item));

        String token = jwtService.generate("user-123");

        mockMvc.perform(get("/api/vault")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .secure(true))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value("item-1"))
                .andExpect(jsonPath("$[0].titleCipher").value("titleCipher"))
                .andExpect(jsonPath("$[0].usernameCipher").value("usernameCipher"));
    }

    @Test
    void createVaultWithoutTokenReturns401() throws Exception {
        mockMvc.perform(post("/api/vault")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}")
                        .secure(true))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void createVaultWithTokenSavesItem() throws Exception {
        when(vaultItemRepository.save(any(VaultItem.class)))
                .thenAnswer(invocation -> {
                    VaultItem saved = invocation.getArgument(0);
                    saved.setId("item-1");
                    saved.setCreatedAt(Instant.parse("2024-01-01T00:00:00Z"));
                    saved.setUpdatedAt(Instant.parse("2024-01-01T00:00:00Z"));
                    return saved;
                });

        String token = jwtService.generate("user-123");

        mockMvc.perform(post("/api/vault")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{" +
                                "\"titleCipher\":\"titleCipher\"," +
                                "\"titleNonce\":\"titleNonce\"," +
                                "\"usernameCipher\":\"usernameCipher\"," +
                                "\"usernameNonce\":\"usernameNonce\"," +
                                "\"passwordCipher\":\"passwordCipher\"," +
                                "\"passwordNonce\":\"passwordNonce\"," +
                                "\"url\":\"https://example.com\"," +
                                "\"notesCipher\":\"notesCipher\"," +
                                "\"notesNonce\":\"notesNonce\"}")
                        .secure(true))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value("item-1"))
                .andExpect(jsonPath("$.titleCipher").value("titleCipher"))
                .andExpect(jsonPath("$.passwordCipher").value("passwordCipher"));

        verify(vaultItemRepository).save(argThat(saved ->
                "user-123".equals(saved.getUserId()) &&
                        "titleCipher".equals(saved.getTitleCipher())));
    }

    @Test
    void updateVaultWithoutTokenReturns401() throws Exception {
        mockMvc.perform(put("/api/vault/item-1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}")
                        .secure(true))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void updateVaultWithTokenUpdatesItem() throws Exception {
        VaultItem existing = new VaultItem();
        existing.setId("item-1");
        existing.setUserId("user-123");
        existing.setTitleCipher("oldTitle");
        existing.setTitleNonce("oldTitleNonce");
        existing.setUsernameCipher("oldUsername");
        existing.setUsernameNonce("oldUsernameNonce");
        existing.setPasswordCipher("oldPassword");
        existing.setPasswordNonce("oldPasswordNonce");
        existing.setUrl("https://old.example.com");
        existing.setNotesCipher("oldNotes");
        existing.setNotesNonce("oldNotesNonce");
        existing.setCreatedAt(Instant.parse("2024-01-01T00:00:00Z"));
        existing.setUpdatedAt(Instant.parse("2024-01-01T00:00:00Z"));

        when(vaultItemRepository.findByIdAndUserId("item-1", "user-123"))
                .thenReturn(Optional.of(existing));
        when(vaultItemRepository.save(any(VaultItem.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        String token = jwtService.generate("user-123");

        mockMvc.perform(put("/api/vault/item-1")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{" +
                                "\"titleCipher\":\"newTitle\"," +
                                "\"titleNonce\":\"newTitleNonce\"," +
                                "\"usernameCipher\":\"newUsername\"," +
                                "\"usernameNonce\":\"newUsernameNonce\"," +
                                "\"passwordCipher\":\"newPassword\"," +
                                "\"passwordNonce\":\"newPasswordNonce\"," +
                                "\"url\":\"https://new.example.com\"," +
                                "\"notesCipher\":\"newNotes\"," +
                                "\"notesNonce\":\"newNotesNonce\"}")
                        .secure(true))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.titleCipher").value("newTitle"))
                .andExpect(jsonPath("$.passwordCipher").value("newPassword"));

        verify(vaultItemRepository).save(argThat(saved ->
                "item-1".equals(saved.getId()) &&
                        "newPassword".equals(saved.getPasswordCipher())));
    }

    @Test
    void deleteVaultWithoutTokenReturns401() throws Exception {
        mockMvc.perform(delete("/api/vault/item-1").secure(true))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void deleteVaultWithTokenRemovesItem() throws Exception {
        VaultItem existing = new VaultItem();
        existing.setId("item-1");
        existing.setUserId("user-123");

        when(vaultItemRepository.findByIdAndUserId("item-1", "user-123"))
                .thenReturn(Optional.of(existing));

        String token = jwtService.generate("user-123");

        mockMvc.perform(delete("/api/vault/item-1")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .secure(true))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ok").value(true));

        verify(vaultItemRepository).delete(argThat(saved -> "item-1".equals(saved.getId())));
    }
}