package com.example.pm.security;

import com.example.pm.config.RateLimitProps;
import com.example.pm.exceptions.ErrorResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Optional;

@Component
public class AuthRateLimitingFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(AuthRateLimitingFilter.class);
    private static final String LOGIN_PATH = "/api/auth/login";
    private static final String REGISTER_PATH = "/api/auth/register";
    private static final String CAPTCHA_FIELD = "captchaToken";

    private final ObjectMapper objectMapper;
    private final RateLimitProps rateLimitProps;
    private final LoginThrottleService loginThrottleService;
    private final CaptchaValidationService captchaValidationService;

    public AuthRateLimitingFilter(ObjectMapper objectMapper,
                                  RateLimitProps rateLimitProps,
                                  LoginThrottleService loginThrottleService,
                                  CaptchaValidationService captchaValidationService) {
        this.objectMapper = objectMapper;
        this.rateLimitProps = rateLimitProps;
        this.loginThrottleService = loginThrottleService;
        this.captchaValidationService = captchaValidationService;
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
        HttpServletRequest workingRequest = request;
        JsonNode body = null;
        try {
            CachedBodyHttpServletRequest cached = new CachedBodyHttpServletRequest(request);
            workingRequest = cached;
            body = readBody(cached);
        } catch (IOException ex) {
            log.debug("Unable to cache request body: {}", ex.getMessage());
            if (ex.getMessage().contains("too large")) {
                writePayloadTooLarge(response);
                return;
            }
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid request");
            return;
        }

        String clientIp = extractClientIp(workingRequest);
        String path = resolvePath(workingRequest);
        String identifier = extractIdentifier(path, body);

        boolean allowed = loginThrottleService.tryAcquire(path, clientIp, identifier);
        if (!allowed) {
            String captchaToken = extractCaptchaToken(workingRequest, body);
            if (!captchaValidationService.validateCaptcha(captchaToken, clientIp)) {
                writeTooManyRequests(response);
                return;
            }
        }

        filterChain.doFilter(workingRequest, response);
    }

    private JsonNode readBody(CachedBodyHttpServletRequest request) {
        byte[] content = request.getCachedBody();
        if (content.length == 0) {
            return null;
        }
        try {
            return objectMapper.readTree(content);
        } catch (IOException e) {
            log.debug("Unable to parse auth request body");
            return null;
        }
    }

    private String extractIdentifier(String path, JsonNode body) {
        if (body == null) {
            return "";
        }
        if (LOGIN_PATH.equals(path)) {
            return getText(body, "email");
        }
        if (REGISTER_PATH.equals(path)) {
            String email = getText(body, "email");
            if (!email.isBlank()) {
                return email;
            }
            return getText(body, "username");
        }
        return "";
    }

    private String extractCaptchaToken(HttpServletRequest request, JsonNode body) {
        if (body != null) {
            String value = getText(body, CAPTCHA_FIELD);
            if (!value.isBlank()) {
                return value;
            }
        }
        String explicitHeader = request.getHeader("X-Captcha-Token");
        if (explicitHeader != null && !explicitHeader.isBlank()) {
            return explicitHeader.trim();
        }
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames != null && headerNames.hasMoreElements()) {
            String name = headerNames.nextElement();
            if (CAPTCHA_FIELD.equalsIgnoreCase(name)) {
                String value = request.getHeader(name);
                if (value != null && !value.isBlank()) {
                    return value.trim();
                }
            }
        }
        String param = request.getParameter(CAPTCHA_FIELD);
        return param == null ? null : param.trim();
    }

    private String getText(JsonNode body, String field) {
        JsonNode node = body.get(field);
        if (node == null || node.isNull()) {
            return "";
        }
        return node.asText("").trim();
    }

    private String extractClientIp(HttpServletRequest request) {
        String remoteAddr = normalizeIp(request.getRemoteAddr());
        if (remoteAddr.isEmpty()) {
            remoteAddr = "unknown";
        }

        if (!rateLimitProps.isTrustedProxy(remoteAddr)) {
            return remoteAddr;
        }

        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor == null || forwardedFor.isBlank()) {
            return remoteAddr;
        }

        String[] parts = forwardedFor.split(",");
        for (String part : parts) {
            String candidate = normalizeIp(part);
            if (!candidate.isEmpty()) {
                return candidate;
            }
        }

        return remoteAddr;
    }

    private String normalizeIp(String ip) {
        if (ip == null) {
            return "";
        }
        String trimmed = ip.trim();
        if (trimmed.isEmpty()) {
            return "";
        }
        return trimmed.toLowerCase(Locale.ROOT);
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

    private void writePayloadTooLarge(HttpServletResponse response) throws IOException {
        response.setStatus(HttpStatus.PAYLOAD_TOO_LARGE.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(),
                new ErrorResponse(HttpStatus.PAYLOAD_TOO_LARGE.value(), "PAYLOAD_TOO_LARGE",
                        "Request body too large"));
    }
}
