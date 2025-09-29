package com.example.pm.auth;

public interface EmailSender {
    void sendVerificationEmail(String email, String username, String verificationLink);
}