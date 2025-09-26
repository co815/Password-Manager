package com.example.pm.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

public class CsrfCookieFilter extends OncePerRequestFilter {

    private final boolean sslEnabled;

    public CsrfCookieFilter(boolean sslEnabled) {
        this.sslEnabled = sslEnabled;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        filterChain.doFilter(request, response);

        CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (token == null) {
            Object attribute = request.getAttribute("_csrf");
            if (attribute instanceof CsrfToken csrfToken) {
                token = csrfToken;
            }
        }
        if (token != null) {
            response.setHeader("X-XSRF-TOKEN", token.getToken());
            rewriteXsrfCookie(response, request);
        }
    }

    private void rewriteXsrfCookie(HttpServletResponse response, HttpServletRequest request) {
        Collection<String> headers = response.getHeaders(HttpHeaders.SET_COOKIE);
        if (headers.isEmpty()) {
            return;
        }

        List<String> rewritten = new ArrayList<>(headers.size());
        for (String header : headers) {
            if (header.startsWith("XSRF-TOKEN=")) {
                rewritten.add(adjustXsrfCookie(header, request));
            } else {
                rewritten.add(header);
            }
        }

        response.setHeader(HttpHeaders.SET_COOKIE, rewritten.get(0));
        for (int i = 1; i < rewritten.size(); i++) {
            response.addHeader(HttpHeaders.SET_COOKIE, rewritten.get(i));
        }
    }

    private String adjustXsrfCookie(String cookieHeader, HttpServletRequest request) {
        String[] segments = cookieHeader.split(";");
        String base = segments[0].trim();
        List<String> attributes = new ArrayList<>();

        for (int i = 1; i < segments.length; i++) {
            String attribute = segments[i].trim();
            if (attribute.isEmpty()) {
                continue;
            }

            String lower = attribute.toLowerCase(Locale.ROOT);
            if ("secure".equals(lower) || lower.startsWith("samesite=")) {
                continue;
            }

            attributes.add(attribute);
        }

        boolean secure = shouldUseSecureCookie(request);
        String sameSite = determineSameSite(request);
        if ("None".equalsIgnoreCase(sameSite) && !secure) {
            sameSite = "Lax";
        }

        if (sameSite != null && !sameSite.isBlank()) {
            attributes.add("SameSite=" + sameSite);
        }
        if (secure) {
            attributes.add("Secure");
        }

        StringBuilder cookie = new StringBuilder(base);
        for (String attribute : attributes) {
            cookie.append("; ").append(attribute);
        }
        return cookie.toString();
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
                        String value = trimmed.substring(6).trim();
                        if ("https".equalsIgnoreCase(value)) {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

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
