package com.example.pm.security;

import com.example.pm.config.AuthCookieProps;
import com.example.pm.model.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@SuppressWarnings("null") // Suppress Spring null-safety false positives
public class AuthSessionService {

    private final JwtService jwtService;
    private final AuthCookieProps authCookieProps;
    private final CsrfTokenRepository csrfTokenRepository;
    private final boolean sslEnabled;

    public AuthSessionService(JwtService jwtService,
            AuthCookieProps authCookieProps,
            CsrfTokenRepository csrfTokenRepository,
            @Value("${server.ssl.enabled:true}") boolean sslEnabled) {
        this.jwtService = jwtService;
        this.authCookieProps = authCookieProps;
        this.csrfTokenRepository = csrfTokenRepository;
        this.sslEnabled = sslEnabled;
    }

    public Session startSession(User user, HttpServletRequest request, HttpServletResponse response) {
        String token = jwtService.generate(user.getId(), user.getTokenVersion());
        ResponseCookie cookie = buildAccessTokenCookie(token, jwtService.getExpiry(),
                shouldUseSecureCookie(request));
        CsrfToken csrfToken = csrfTokenRepository.generateToken(request);
        request.setAttribute(CsrfToken.class.getName(), csrfToken);
        request.setAttribute(csrfToken.getParameterName(), csrfToken);
        csrfTokenRepository.saveToken(csrfToken, request, response);
        return new Session(token, cookie, csrfToken);
    }

    public ResponseCookie buildClearingCookie(HttpServletRequest request) {
        return buildAccessTokenCookie("", Duration.ZERO, shouldUseSecureCookie(request));
    }

    private ResponseCookie buildAccessTokenCookie(String value, Duration maxAge, boolean secure) {
        String sameSite = authCookieProps.getSameSiteAttribute();
        boolean requiresCrossSite = sameSite != null && sameSite.equalsIgnoreCase("None");

        ResponseCookie.ResponseCookieBuilder builder = ResponseCookie.from("accessToken", value != null ? value : "")
                .path("/")
                .httpOnly(true)
                .secure(secure || requiresCrossSite);

        if (maxAge != null) {
            if (maxAge.isZero() || maxAge.isNegative()) {
                builder.maxAge(Duration.ZERO);
            } else {
                builder.maxAge(maxAge);
            }
        }

        if (sameSite != null && !sameSite.isBlank()) {
            builder.sameSite(sameSite);
        }
        return builder.build();
    }

    private boolean shouldUseSecureCookie(HttpServletRequest request) {
        if (!sslEnabled) {
            return false;
        }

        if (request == null) {
            return true;
        }

        if (forwardedProtoIsHttp(request)) {
            return false;
        }

        return request.isSecure();
    }

    private boolean forwardedProtoIsHttp(HttpServletRequest request) {
        String forwardedProto = request.getHeader("X-Forwarded-Proto");
        if (forwardedProto != null) {
            for (String proto : forwardedProto.split(",")) {
                if ("http".equalsIgnoreCase(proto.trim())) {
                    return true;
                }
            }
        }

        String forwarded = request.getHeader("Forwarded");
        if (forwarded != null) {
            for (String segment : forwarded.split(",")) {
                for (String part : segment.split(";")) {
                    String trimmed = part.trim();
                    if (trimmed.regionMatches(true, 0, "proto=", 0, 6)) {
                        String value = trimmed.substring(6).trim();
                        if ("http".equalsIgnoreCase(value)) {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

    public record Session(String token, ResponseCookie cookie, CsrfToken csrfToken) {
    }
}