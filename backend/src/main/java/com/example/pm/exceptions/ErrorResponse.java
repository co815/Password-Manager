package com.example.pm.exceptions;

public record ErrorResponse(int status, String type, String message) {}