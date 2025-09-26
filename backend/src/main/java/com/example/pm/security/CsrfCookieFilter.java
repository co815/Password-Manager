package com.example.pm.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

public class CsrfCookieFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        filterChain.doFilter(request, response);

        CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (token != null) {
            response.setHeader("X-CSRF-TOKEN", token.getToken());
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

        String origin = request.getHeader("Origin");
        boolean insecureOrigin = origin != null && !origin.toLowerCase(Locale.ROOT).startsWith("https://");
        if (!insecureOrigin && request.isSecure()) {
            attributes.add("Secure");
        }

        attributes.add("SameSite=" + (insecureOrigin ? "Lax" : "Strict"));

        StringBuilder cookie = new StringBuilder(base);
        for (String attribute : attributes) {
            cookie.append("; ").append(attribute);
        }
        return cookie.toString();
    }
}
