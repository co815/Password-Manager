package com.example.pm.security;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.Locale;

class StrictCookieCsrfTokenRepository implements CsrfTokenRepository {

    private final CookieCsrfTokenRepository delegate = new CookieCsrfTokenRepository();
    private final boolean sslEnabled;

    StrictCookieCsrfTokenRepository(boolean sslEnabled) {
        this.sslEnabled = sslEnabled;
    }

    public void setCookieName(String cookieName) {
        delegate.setCookieName(cookieName);
    }

    public void setHeaderName(String headerName) {
        delegate.setHeaderName(headerName);
    }

    public void setCookieHttpOnly(boolean cookieHttpOnly) {
        delegate.setCookieHttpOnly(cookieHttpOnly);
    }

    public void setCookiePath(String cookiePath) {
        delegate.setCookiePath(cookiePath);
    }

    @Override
    public CsrfToken generateToken(HttpServletRequest request) {
        return delegate.generateToken(request);
    }

    @Override
    public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
        HttpServletResponseWrapper wrapper = new HttpServletResponseWrapper(response) {
            @Override
            public void addCookie(Cookie cookie) {
                if (cookie != null && "XSRF-TOKEN".equals(cookie.getName())) {
                    ResponseCookie.ResponseCookieBuilder builder = ResponseCookie.from(
                                    cookie.getName(),
                                    cookie.getValue() != null ? cookie.getValue() : ""
                            )
                            .httpOnly(false)
                            .sameSite(determineSameSite(request));
                    if (cookie.getDomain() != null && !cookie.getDomain().isBlank()) {
                        builder.domain(cookie.getDomain());
                    }
                    if (cookie.getMaxAge() >= 0) {
                        builder.maxAge(Duration.ofSeconds(cookie.getMaxAge()));
                    }
                    if (shouldUseSecureCookie(request)) {
                        builder.secure(true);
                    }
                    super.addHeader(HttpHeaders.SET_COOKIE, builder.build().toString());
                } else {
                    super.addCookie(cookie);
                }
            }
        };
        delegate.saveToken(token, request, wrapper);
    }

    @Override
    public CsrfToken loadToken(HttpServletRequest request) {
        return delegate.loadToken(request);
    }

    private boolean shouldUseSecureCookie(HttpServletRequest request) {
        if (!sslEnabled) {
            return false;
        }
        if (request == null) {
            return true;
        }
        if (request.isSecure()) {
            return true;
        }
        String forwardedProto = request.getHeader("X-Forwarded-Proto");
        if (forwardedProto != null) {
            for (String proto : forwardedProto.split(",")) {
                if ("https".equalsIgnoreCase(proto.trim())) {
                    return true;
                }
            }
        }
        String forwarded = request.getHeader("Forwarded");
        if (forwarded != null) {
            for (String segment : forwarded.split(",")) {
                for (String part : segment.split(";")) {
                    String trimmed = part.trim();
                    if (trimmed.toLowerCase(Locale.ROOT).startsWith("proto=")) {
                        String value = trimmed.substring(6);
                        if ("https".equalsIgnoreCase(value.trim())) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
        private String determineSameSite(HttpServletRequest request) {
            if (request == null) {
                return "Strict";
            }

            String origin = request.getHeader("Origin");
            if (origin == null || origin.isBlank()) {
                return "Strict";
            }

            try {
                URI originUri = new URI(origin);
                String originHost = originUri.getHost();
                if (originHost == null) {
                    return "None";
                }

                String requestHost = request.getServerName();
                if (!originHost.equalsIgnoreCase(requestHost)) {
                    return "None";
                }

                String originScheme = originUri.getScheme();
                String requestScheme = resolveScheme(request);
                if (originScheme != null && originScheme.equalsIgnoreCase(requestScheme)) {
                    return "Strict";
                }
            } catch (URISyntaxException ignored) {
                return "None";
            }

            return "None";
        }

        private String resolveScheme(HttpServletRequest request) {
            if (request.isSecure()) {
                return "https";
            }

            String forwardedProto = request.getHeader("X-Forwarded-Proto");
            if (forwardedProto != null) {
                for (String proto : forwardedProto.split(",")) {
                    if (!proto.isBlank()) {
                        return proto.trim().toLowerCase(Locale.ROOT);
                    }
                }
            }

            String forwarded = request.getHeader("Forwarded");
            if (forwarded != null) {
                for (String segment : forwarded.split(",")) {
                    for (String part : segment.split(";")) {
                        String trimmed = part.trim();
                        if (trimmed.regionMatches(true, 0, "proto=", 0, 6)) {
                            return trimmed.substring(6).trim().toLowerCase(Locale.ROOT);
                        }
                    }
                }
            }

            return request.getScheme();
        }
}