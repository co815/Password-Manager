package com.example.pm.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

@Service
public class JwtService {
    private final SecretKey key;
    private final long expiryMinutes;

    public JwtService(@Value("${app.jwt.secret}") String secret,
                      @Value("${app.jwt.expiryMinutes:15}") long expiryMinutes) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.expiryMinutes = expiryMinutes;
    }

    public String generate(String subject, int tokenVersion) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(subject)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(expiryMinutes * 60)))
                .claims(Map.of("tv", tokenVersion))
                .signWith(key)
                .compact();
    }

    public JwtPayload validate(String token) {
        var claims = Jwts.parser().verifyWith(key).build()
                .parseSignedClaims(token)
                .getPayload();
        Integer tokenVersion = claims.get("tv", Integer.class);
        return new JwtPayload(claims.getSubject(), tokenVersion != null ? tokenVersion : 0);
    }

    public Duration getExpiry() {
        return Duration.ofMinutes(expiryMinutes);
    }

    public record JwtPayload(String subject, int tokenVersion) {}
}
