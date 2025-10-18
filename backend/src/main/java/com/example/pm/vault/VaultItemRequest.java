package com.example.pm.vault;

import java.util.Set;

public record VaultItemRequest(
        String titleCipher,
        String titleNonce,
        String usernameCipher,
        String usernameNonce,
        String passwordCipher,
        String passwordNonce,
        String url,
        String notesCipher,
        String notesNonce,
        Boolean favorite,
        Set<String> collections
) {
}
