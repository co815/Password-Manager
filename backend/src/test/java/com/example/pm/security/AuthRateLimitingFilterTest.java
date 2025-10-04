package com.example.pm.security;

import com.example.pm.config.CaptchaProps;
import com.example.pm.config.RateLimitProps;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.springframework.web.client.RestClient;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class AuthRateLimitingFilterTest {

    private static final String CLIENT_IP = "203.0.113.10";

    private MockMvc mockMvc;
    private MutableClock clock;
    private RateLimitProps rateLimitProps;
    private RecordingCaptchaValidationService captchaValidationService;

    @BeforeEach
    void setUp() {
        clock = new MutableClock();
        rateLimitProps = new RateLimitProps();
        captchaValidationService = new RecordingCaptchaValidationService();
        LoginThrottleService loginThrottleService = new LoginThrottleService(
                new InMemoryLoginThrottleRepository(), rateLimitProps, clock);
        AuthRateLimitingFilter filter = new AuthRateLimitingFilter(
                new ObjectMapper(), rateLimitProps, loginThrottleService, captchaValidationService);
        mockMvc = MockMvcBuilders.standaloneSetup(new TestAuthController())
                .addFilters(filter)
                .build();
    }

    @Test
    void loginRateLimitPerMinute() throws Exception {
        for (int i = 0; i < 10; i++) {
            mockMvc.perform(post("/api/auth/login")
                            .content(loginPayload("user@example.com", null))
                            .contentType(MediaType.APPLICATION_JSON)
                            .with(client(CLIENT_IP)))
                    .andExpect(status().isOk());
        }

        mockMvc.perform(post("/api/auth/login")
                        .content(loginPayload("user@example.com", null))
                        .contentType(MediaType.APPLICATION_JSON)
                        .with(client(CLIENT_IP)))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    void registerRateLimitPerMinute() throws Exception {
        for (int i = 0; i < 10; i++) {
            mockMvc.perform(post("/api/auth/register")
                            .content(loginPayload("user@example.com", null))
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
        for (int block = 0; block < 5; block++) {
            for (int i = 0; i < 10; i++) {
                mockMvc.perform(post("/api/auth/login")
                                .content(loginPayload("user@example.com", null))
                                .contentType(MediaType.APPLICATION_JSON)
                                .with(client(CLIENT_IP)))
                        .andExpect(status().isOk());
            }
            if (block < 4) {
                clock.advanceSeconds(61);
            }
        }

        clock.advanceSeconds(61);

        mockMvc.perform(post("/api/auth/login")
                        .content(loginPayload("user@example.com", null))
                        .contentType(MediaType.APPLICATION_JSON)
                        .with(client(CLIENT_IP)))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    void registerRateLimitPerHour() throws Exception {
        for (int block = 0; block < 5; block++) {
            for (int i = 0; i < 10; i++) {
                mockMvc.perform(post("/api/auth/register")
                                .content(registerPayload("user@example.com"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .with(client(CLIENT_IP)))
                        .andExpect(status().isOk());
            }
            if (block < 4) {
                clock.advanceSeconds(61);
            }
        }

        clock.advanceSeconds(61);

        mockMvc.perform(post("/api/auth/register")
                        .content(registerPayload("user@example.com"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .with(client(CLIENT_IP)))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    void captchaBypassesLimit() throws Exception {
        for (int i = 0; i < 10; i++) {
            mockMvc.perform(post("/api/auth/login")
                            .content(loginPayload("user@example.com", null))
                            .contentType(MediaType.APPLICATION_JSON)
                            .with(client(CLIENT_IP)))
                    .andExpect(status().isOk());
        }

        mockMvc.perform(post("/api/auth/login")
                        .content(loginPayload("user@example.com", null))
                        .contentType(MediaType.APPLICATION_JSON)
                        .with(client(CLIENT_IP)))
                .andExpect(status().isTooManyRequests());

        captchaValidationService.allow("valid-token");

        mockMvc.perform(post("/api/auth/login")
                        .content(loginPayload("user@example.com", "valid-token"))
                        .contentType(MediaType.APPLICATION_JSON)
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

        for (int i = 0; i < 10; i++) {
            mockMvc.perform(post("/api/auth/login")
                            .content(loginPayload("user@example.com", null))
                            .contentType(MediaType.APPLICATION_JSON)
                            .with(client(proxyIp, spoofedIp)))
                    .andExpect(status().isOk());
        }

        mockMvc.perform(post("/api/auth/login")
                        .content(loginPayload("user@example.com", null))
                        .contentType(MediaType.APPLICATION_JSON)
                        .with(client(proxyIp, "198.51.100.11")))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    void acceptsForwardedHeaderWhenProxyIsTrusted() throws Exception {
        String proxyIp = "198.51.100.10";
        String clientIp = "203.0.113.20";
        rateLimitProps.setTrustedProxies(List.of(proxyIp));

        for (int i = 0; i < 10; i++) {
            mockMvc.perform(post("/api/auth/login")
                            .content(loginPayload("user@example.com", null))
                            .contentType(MediaType.APPLICATION_JSON)
                            .with(client(proxyIp, clientIp)))
                    .andExpect(status().isOk());
        }

        mockMvc.perform(post("/api/auth/login")
                        .content(loginPayload("user@example.com", null))
                        .contentType(MediaType.APPLICATION_JSON)
                        .with(client(proxyIp, clientIp)))
                .andExpect(status().isTooManyRequests());
    }

    private String loginPayload(String email, String captchaToken) {
        StringBuilder builder = new StringBuilder();
        builder.append('{')
                .append("\"email\":\"").append(email).append("\"");
        if (captchaToken != null) {
            builder.append(',').append("\"captchaToken\":\"").append(captchaToken).append("\"");
        }
        builder.append('}');
        return builder.toString();
    }

    private String registerPayload(String email) {
        return "{" +
                "\"email\":\"" + email + "\"," +
                "\"username\":\"user\"," +
                "\"verifier\":\"ver\"," +
                "\"saltClient\":\"salt\"," +
                "\"dekEncrypted\":\"dek\"," +
                "\"dekNonce\":\"nonce\"}";
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

    static class MutableClock extends Clock {

        private Instant current = Instant.EPOCH;
        private ZoneId zone = ZoneId.of("UTC");

        void advanceSeconds(long seconds) {
            current = current.plusSeconds(seconds);
        }

        @Override
        public ZoneId getZone() {
            return zone;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            MutableClock copy = new MutableClock();
            copy.current = this.current;
            copy.zone = zone;
            return copy;
        }

        @Override
        public Instant instant() {
            return current;
        }
    }

    static class InMemoryLoginThrottleRepository implements LoginThrottleRepository {

        private final Map<String, LoginThrottleEntry> store = new ConcurrentHashMap<>();

        @Override
        public Optional<LoginThrottleEntry> findById(String id) {
            LoginThrottleEntry entry = store.get(id);
            if (entry == null) {
                return Optional.empty();
            }
            return Optional.of(copy(entry));
        }

        @Override
        public LoginThrottleEntry save(LoginThrottleEntry entry) {
            LoginThrottleEntry copy = copy(entry);
            long nextVersion = entry.getVersion() == null ? 0L : entry.getVersion() + 1;
            copy.setVersion(nextVersion);
            entry.setVersion(nextVersion);
            store.put(copy.getId(), copy);
            return entry;
        }

        private LoginThrottleEntry copy(LoginThrottleEntry original) {
            LoginThrottleEntry clone = new LoginThrottleEntry();
            clone.setId(original.getId());
            clone.setMinuteWindowStart(original.getMinuteWindowStart());
            clone.setMinuteCount(original.getMinuteCount());
            clone.setHourWindowStart(original.getHourWindowStart());
            clone.setHourCount(original.getHourCount());
            clone.setUpdatedAt(original.getUpdatedAt());
            clone.setVersion(original.getVersion());
            return clone;
        }
    }

    static class RecordingCaptchaValidationService extends CaptchaValidationService {

        private final Set<String> validTokens = ConcurrentHashMap.newKeySet();

        RecordingCaptchaValidationService() {
            super(new CaptchaProps(), RestClient.create());
        }

        void allow(String token) {
            validTokens.add(token);
        }

        @Override
        public boolean validateCaptcha(String token, String remoteIp) {
            return token != null && validTokens.contains(token);
        }
    }
}