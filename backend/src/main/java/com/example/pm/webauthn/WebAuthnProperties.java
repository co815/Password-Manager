package com.example.pm.webauthn;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@Component
@ConfigurationProperties(prefix = "app.webauthn")
public class WebAuthnProperties {

    private String relyingPartyId = "localhost";
    private String relyingPartyName = "Password Manager";
    private List<String> origins = new ArrayList<>();
    private long challengeTtlSeconds = 300;

    public String getRelyingPartyId() {
        return relyingPartyId;
    }

    public void setRelyingPartyId(String relyingPartyId) {
        this.relyingPartyId = relyingPartyId;
    }

    public String getRelyingPartyName() {
        return relyingPartyName;
    }

    public void setRelyingPartyName(String relyingPartyName) {
        this.relyingPartyName = relyingPartyName;
    }

    public List<String> getOrigins() {
        return origins;
    }

    public void setOrigins(List<String> origins) {
        this.origins = origins != null ? new ArrayList<>(origins) : new ArrayList<>();
    }

    public long getChallengeTtlSeconds() {
        return challengeTtlSeconds;
    }

    public void setChallengeTtlSeconds(long challengeTtlSeconds) {
        this.challengeTtlSeconds = challengeTtlSeconds;
    }

    public Duration getChallengeTtl() {
        long seconds = challengeTtlSeconds <= 0 ? 300 : challengeTtlSeconds;
        return Duration.ofSeconds(seconds);
    }
}
