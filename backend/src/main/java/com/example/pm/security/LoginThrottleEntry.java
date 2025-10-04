package com.example.pm.security;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Version;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Duration;
import java.time.Instant;

@Document(collection = "login_throttle")
class LoginThrottleEntry {

    private static final Duration MINUTE_WINDOW = Duration.ofMinutes(1);
    private static final Duration HOUR_WINDOW = Duration.ofHours(1);

    @Id
    private String id;

    private Instant minuteWindowStart;
    private int minuteCount;

    private Instant hourWindowStart;
    private int hourCount;

    @Indexed(expireAfterSeconds = 7200)
    private Instant updatedAt;

    @Version
    private Long version;

    LoginThrottleEntry() {
        // For Spring Data
    }

    LoginThrottleEntry(String id, Instant now) {
        this.id = id;
        this.minuteWindowStart = now;
        this.hourWindowStart = now;
        this.updatedAt = now;
        this.minuteCount = 0;
        this.hourCount = 0;
    }

    boolean recordAttempt(Instant now, int perMinuteLimit, int perHourLimit) {
        resetWindowsIfExpired(now);
        updatedAt = now;

        if (minuteCount >= perMinuteLimit || hourCount >= perHourLimit) {
            return false;
        }

        minuteCount++;
        hourCount++;
        return true;
    }

    private void resetWindowsIfExpired(Instant now) {
        if (minuteWindowStart == null || now.isAfter(minuteWindowStart.plus(MINUTE_WINDOW))) {
            minuteWindowStart = now;
            minuteCount = 0;
        }
        if (hourWindowStart == null || now.isAfter(hourWindowStart.plus(HOUR_WINDOW))) {
            hourWindowStart = now;
            hourCount = 0;
        }
    }

    String getId() {
        return id;
    }

    void setId(String id) {
        this.id = id;
    }

    Instant getUpdatedAt() {
        return updatedAt;
    }

    void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }

    Long getVersion() {
        return version;
    }

    void setVersion(Long version) {
        this.version = version;
    }

    Instant getMinuteWindowStart() {
        return minuteWindowStart;
    }

    void setMinuteWindowStart(Instant minuteWindowStart) {
        this.minuteWindowStart = minuteWindowStart;
    }

    int getMinuteCount() {
        return minuteCount;
    }

    void setMinuteCount(int minuteCount) {
        this.minuteCount = minuteCount;
    }

    Instant getHourWindowStart() {
        return hourWindowStart;
    }

    void setHourWindowStart(Instant hourWindowStart) {
        this.hourWindowStart = hourWindowStart;
    }

    int getHourCount() {
        return hourCount;
    }

    void setHourCount(int hourCount) {
        this.hourCount = hourCount;
    }
}