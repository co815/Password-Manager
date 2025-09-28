package com.example.pm.security;

import com.example.pm.config.RateLimitProps;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.TimeMeter;
import io.github.bucket4j.Refill;
import io.github.bucket4j.local.LocalBucketBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class AuthRateLimitingFilterTest {

    private static final String CLIENT_IP = "203.0.113.10";

    private MockMvc mockMvc;
    private TestTimeMeter timeMeter;
    private AuthRateLimitingFilter filter;
    private RateLimitProps rateLimitProps;

    @BeforeEach
    void setUp() {
        timeMeter = new TestTimeMeter();
        Supplier<Bucket> supplier = () -> new LocalBucketBuilder()
                .withCustomTimePrecision(timeMeter)
                .addLimit(Bandwidth.classic(10, Refill.greedy(10, Duration.ofMinutes(1))))
                .addLimit(Bandwidth.classic(50, Refill.intervally(50, Duration.ofHours(1))))
                .build();
        rateLimitProps = new RateLimitProps();
        filter = new AuthRateLimitingFilter(new ObjectMapper(), rateLimitProps, supplier);
        mockMvc = MockMvcBuilders.standaloneSetup(new TestAuthController())
                .addFilters(filter)
                .build();
        filter.getBuckets().clear();
        timeMeter.reset();
    }

    @Test
    void loginRateLimitPerMinute() throws Exception {
        for (int i = 0; i < 10; i++) {
            mockMvc.perform(post("/api/auth/login")
                            .content("{}")
                            .contentType(MediaType.APPLICATION_JSON)
                            .with(client(CLIENT_IP)))
                    .andExpect(status().isOk());
        }

        mockMvc.perform(post("/api/auth/login")
                        .content("{}")
                        .contentType(MediaType.APPLICATION_JSON)
                        .with(client(CLIENT_IP)))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    void registerRateLimitPerMinute() throws Exception {
        for (int i = 0; i < 10; i++) {
            mockMvc.perform(post("/api/auth/register")
                            .content("{}")
                            .contentType(MediaType.APPLICATION_JSON)
                            .with(client(CLIENT_IP)))
                    .andExpect(status().isOk());
        }

        mockMvc.perform(post("/api/auth/register")
                        .content("{}")
                        .contentType(MediaType.APPLICATION_JSON)
                        .with(client(CLIENT_IP)))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    void loginRateLimitPerHour() throws Exception {
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 10; j++) {
                mockMvc.perform(post("/api/auth/login")
                                .content("{}")
                                .contentType(MediaType.APPLICATION_JSON)
                                .with(client(CLIENT_IP)))
                        .andExpect(status().isOk());
            }
            if (i < 4) {
                timeMeter.advanceSeconds(61);
            }
        }

        timeMeter.advanceSeconds(61);

        mockMvc.perform(post("/api/auth/login")
                        .content("{}")
                        .contentType(MediaType.APPLICATION_JSON)
                        .with(client(CLIENT_IP)))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    void registerRateLimitPerHour() throws Exception {
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 10; j++) {
                mockMvc.perform(post("/api/auth/register")
                                .content("{}")
                                .contentType(MediaType.APPLICATION_JSON)
                                .with(client(CLIENT_IP)))
                        .andExpect(status().isOk());
            }
            if (i < 4) {
                timeMeter.advanceSeconds(61);
            }
        }

        timeMeter.advanceSeconds(61);

        mockMvc.perform(post("/api/auth/register")
                        .content("{}")
                        .contentType(MediaType.APPLICATION_JSON)
                        .with(client(CLIENT_IP)))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    void captchaBypassesLimit() throws Exception {
        for (int i = 0; i < 10; i++) {
            mockMvc.perform(post("/api/auth/login")
                            .content("{}")
                            .contentType(MediaType.APPLICATION_JSON)
                            .with(client(CLIENT_IP)))
                    .andExpect(status().isOk());
        }

        mockMvc.perform(post("/api/auth/login")
                        .content("{}")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(AuthRateLimitingFilter.CAPTCHA_FLAG, "true")
                        .with(client(CLIENT_IP)))
                .andExpect(status().isOk());
    }

    @Test
    void nonAuthEndpointsAreNotRateLimited() throws Exception {
        for (int i = 0; i < 12; i++) {
            mockMvc.perform(post("/api/auth/login")
                            .content("{}")
                            .contentType(MediaType.APPLICATION_JSON)
                            .with(client(CLIENT_IP)))
                    .andExpect(i < 10 ? status().isOk() : status().isTooManyRequests());
        }

        mockMvc.perform(get("/api/health").with(client(CLIENT_IP)))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/profile/update")
                        .content("{}")
                        .contentType(MediaType.APPLICATION_JSON)
                        .with(client(CLIENT_IP)))
                .andExpect(status().isOk());
    }

    @Test
    void ignoresSpoofedForwardedHeaderWhenProxyNotTrusted() throws Exception {
        String proxyIp = "198.51.100.10";
        String spoofedIp = "203.0.113.20";

        mockMvc.perform(post("/api/auth/login")
                        .content("{}")
                        .contentType(MediaType.APPLICATION_JSON)
                        .with(client(proxyIp, spoofedIp)))
                .andExpect(status().isOk());

        assertThat(filter.getBuckets()).containsKey(proxyIp);
        assertThat(filter.getBuckets()).doesNotContainKey(spoofedIp);
    }

    @Test
    void acceptsForwardedHeaderWhenProxyIsTrusted() throws Exception {
        String proxyIp = "198.51.100.10";
        String clientIp = "203.0.113.20";
        rateLimitProps.setTrustedProxies(List.of(proxyIp));

        mockMvc.perform(post("/api/auth/login")
                        .content("{}")
                        .contentType(MediaType.APPLICATION_JSON)
                        .with(client(proxyIp, clientIp)))
                .andExpect(status().isOk());

        assertThat(filter.getBuckets()).containsKey(clientIp);
        assertThat(filter.getBuckets()).doesNotContainKey(proxyIp);
    }

    private RequestPostProcessor client(String ip) {
        return client(ip, ip);
    }

    private RequestPostProcessor client(String remoteIp, String forwardedFor) {
        return request -> {
            if (forwardedFor != null) {
                request.addHeader("X-Forwarded-For", forwardedFor);
            }
            request.setRemoteAddr(remoteIp);
            return request;
        };
    }

    @RestController
    @RequestMapping("/api")
    static class TestAuthController {

        @PostMapping("/auth/login")
        String login() {
            return "ok";
        }

        @PostMapping("/auth/register")
        String register() {
            return "ok";
        }

        @PostMapping("/profile/update")
        String other() {
            return "ok";
        }

        @GetMapping("/health")
        String health() {
            return "ok";
        }
    }

    static class TestTimeMeter implements TimeMeter {

        private final AtomicLong nanos = new AtomicLong();

        @Override
        public long currentTimeNanos() {
            return nanos.get();
        }

        @Override
        public boolean isWallClockBased() {
            return false;
        }

        void advanceSeconds(long seconds) {
            nanos.addAndGet(Duration.ofSeconds(seconds).toNanos());
        }

        void reset() {
            nanos.set(0L);
        }
    }
}