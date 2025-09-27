package com.example.pm.security;

import com.example.pm.exceptions.ErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.local.LocalBucketBuilder;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Enumeration;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Supplier;

@Component
public class AuthRateLimitingFilter extends OncePerRequestFilter {

    static final String CAPTCHA_FLAG = "CAPTCHA_VALID";
    private static final String LOGIN_PATH = "/api/auth/login";
    private static final String REGISTER_PATH = "/api/auth/register";

    private final ObjectMapper objectMapper;
    private final ConcurrentMap<String, Bucket> buckets = new ConcurrentHashMap<>();
    private final Supplier<Bucket> bucketSupplier;

    @Autowired
    public AuthRateLimitingFilter(ObjectMapper objectMapper) {
        this(objectMapper, AuthRateLimitingFilter::createDefaultBucket);
    }

    AuthRateLimitingFilter(ObjectMapper objectMapper, Supplier<Bucket> bucketSupplier) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
        this.bucketSupplier = Objects.requireNonNull(bucketSupplier, "bucketSupplier");
    }

    private static Bucket createDefaultBucket() {
        Bandwidth perMinute = Bandwidth.builder()
                .capacity(10)
                .refillGreedy(10, Duration.ofMinutes(1))
                .build();
        Bandwidth perHour = Bandwidth.builder()
                .capacity(50)
                .refillIntervally(50, Duration.ofHours(1))
                .build();

        return new LocalBucketBuilder()
                .addLimit(perMinute)
                .addLimit(perHour)
                .build();
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            return true;
        }

        String path = resolvePath(request);
        return !LOGIN_PATH.equals(path) && !REGISTER_PATH.equals(path);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String clientIp = extractClientIp(request);
        Bucket bucket = buckets.computeIfAbsent(clientIp, key -> bucketSupplier.get());

        boolean allowed = bucket.tryConsume(1);
        if (!allowed && !isCaptchaValid(request)) {
            writeTooManyRequests(response);
            return;
        }

        filterChain.doFilter(request, response);
    }

    protected boolean isCaptchaValid(HttpServletRequest request) {
        if (hasTrueAttribute(request)) {
            return true;
        }
        if (hasTrueHeader(request)) {
            return true;
        }
        return hasTrueParameter(request);
    }

    private boolean hasTrueAttribute(HttpServletRequest request) {
        Enumeration<String> names = request.getAttributeNames();
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            if (CAPTCHA_FLAG.equalsIgnoreCase(name)) {
                Object value = request.getAttribute(name);
                if (value != null && Boolean.parseBoolean(value.toString())) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean hasTrueHeader(HttpServletRequest request) {
        Enumeration<String> names = request.getHeaderNames();
        while (names != null && names.hasMoreElements()) {
            String name = names.nextElement();
            if (CAPTCHA_FLAG.equalsIgnoreCase(name)) {
                String value = request.getHeader(name);
                if (value != null && Boolean.parseBoolean(value)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean hasTrueParameter(HttpServletRequest request) {
        Map<String, String[]> params = request.getParameterMap();
        for (Map.Entry<String, String[]> entry : params.entrySet()) {
            if (CAPTCHA_FLAG.equalsIgnoreCase(entry.getKey())) {
                String[] values = entry.getValue();
                if (values != null) {
                    for (String value : values) {
                        if (value != null && Boolean.parseBoolean(value)) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    private String extractClientIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            String[] parts = forwardedFor.split(",");
            if (parts.length > 0) {
                String candidate = parts[0].trim();
                if (!candidate.isEmpty()) {
                    return candidate;
                }
            }
        }
        return Optional.ofNullable(request.getRemoteAddr()).orElse("unknown");
    }

    private String resolvePath(HttpServletRequest request) {
        String uri = Optional.ofNullable(request.getRequestURI()).orElse("");
        String contextPath = Optional.ofNullable(request.getContextPath()).orElse("");
        if (!contextPath.isEmpty() && uri.startsWith(contextPath)) {
            return uri.substring(contextPath.length());
        }
        return uri;
    }

    private void writeTooManyRequests(HttpServletResponse response) throws IOException {
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(),
                new ErrorResponse(HttpStatus.TOO_MANY_REQUESTS.value(), "TOO_MANY_REQUESTS",
                        "Too many authentication attempts"));
    }

    ConcurrentMap<String, Bucket> getBuckets() {
        return buckets;
    }
}