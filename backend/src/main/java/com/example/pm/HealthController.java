package com.example.pm;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

@RestController
public class HealthController {
    @GetMapping("/api/health")
    public Map<String, Object> health() { return Map.of("ok", true); }

    @GetMapping("/api/andrei123")
    public Map<String, Object> andrei123() { return Map.of("andrei123", true);}
}
