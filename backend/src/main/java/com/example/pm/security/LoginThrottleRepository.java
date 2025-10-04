package com.example.pm.security;

import java.util.Optional;

interface LoginThrottleRepository {

    Optional<LoginThrottleEntry> findById(String id);

    LoginThrottleEntry save(LoginThrottleEntry entry);
}