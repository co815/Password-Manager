package com.example.pm;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

@RestController
public class Error {
    @GetMapping("/api/error")
    public Map<String, Object> error() { return Map.of("error", true); }
}