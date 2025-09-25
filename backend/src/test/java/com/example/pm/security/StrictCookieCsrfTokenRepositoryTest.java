package com.example.pm.security;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class StrictCookieCsrfTokenRepositoryTest {

    @Test
    void downgradedSameSiteIsAppliedWhenSecureCookieUnavailable() {
        StrictCookieCsrfTokenRepository repository = new StrictCookieCsrfTokenRepository(false);
        repository.setCookieName("XSRF-TOKEN");
        repository.setHeaderName("X-CSRF-TOKEN");
        repository.setCookieHttpOnly(false);
        repository.setCookiePath("/");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("localhost");
        request.addHeader("Origin", "http://127.0.0.1:5173");

        MockHttpServletResponse response = new MockHttpServletResponse();

        CsrfToken token = repository.generateToken(request);
        repository.saveToken(token, request, response);

        List<String> cookies = response.getHeaders(HttpHeaders.SET_COOKIE);
        assertThat(cookies).isNotEmpty();
        String xsrfCookie = cookies.stream()
                .filter(header -> header.startsWith("XSRF-TOKEN=") || header.contains("XSRF-TOKEN"))
                .findFirst()
                .orElseThrow();

        assertThat(xsrfCookie).contains("SameSite=Lax");
        assertThat(xsrfCookie).doesNotContain("Secure");
    }

    @Test
    void sameSiteNoneIsRetainedWhenSecureCookieAvailable() {
        StrictCookieCsrfTokenRepository repository = new StrictCookieCsrfTokenRepository(true);
        repository.setCookieName("XSRF-TOKEN");
        repository.setHeaderName("X-CSRF-TOKEN");
        repository.setCookieHttpOnly(false);
        repository.setCookiePath("/");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setSecure(true);
        request.setServerName("localhost");
        request.addHeader("Origin", "http://localhost:5173");

        MockHttpServletResponse response = new MockHttpServletResponse();

        CsrfToken token = repository.generateToken(request);
        repository.saveToken(token, request, response);

        List<String> cookies = response.getHeaders(HttpHeaders.SET_COOKIE);
        assertThat(cookies).isNotEmpty();
        String xsrfCookie = cookies.stream()
                .filter(header -> header.startsWith("XSRF-TOKEN=") || header.contains("XSRF-TOKEN"))
                .findFirst()
                .orElseThrow();

        assertThat(xsrfCookie).contains("SameSite=None");
        assertThat(xsrfCookie).contains("Secure");
    }
}