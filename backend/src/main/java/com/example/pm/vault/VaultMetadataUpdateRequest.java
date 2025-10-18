package com.example.pm.vault;

import java.util.Set;

public record VaultMetadataUpdateRequest(Boolean favorite, Set<String> collections) {
}
