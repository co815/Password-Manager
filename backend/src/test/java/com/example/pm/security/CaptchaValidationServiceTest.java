package com.example.pm.security;

import com.example.pm.config.CaptchaProps;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

@SuppressWarnings("null")
class CaptchaValidationServiceTest {

    @Test
    void returnsTrueWhenCaptchaDisabled() {
        CaptchaProps props = new CaptchaProps();
        props.setProvider(CaptchaProps.Provider.NONE);

        CaptchaValidationService service = new CaptchaValidationService(props, RestClient.create());

        assertThat(service.validateCaptcha(null, null)).isTrue();
        assertThat(service.validateCaptcha("token", "127.0.0.1")).isTrue();
    }

    @Test
    void rejectsCaptchaWhenSecretMissing() {
        CaptchaProps props = new CaptchaProps();
        props.setProvider(CaptchaProps.Provider.RECAPTCHA);
        props.setSecretKey(null);

        CaptchaValidationService service = new CaptchaValidationService(props, RestClient.create());

        assertThat(service.validateCaptcha("token", "127.0.0.1")).isFalse();
    }

    @Test
    void rejectsCaptchaWhenTokenMissing() {
        CaptchaProps props = new CaptchaProps();
        props.setProvider(CaptchaProps.Provider.RECAPTCHA);
        props.setSecretKey("secret-value");

        CaptchaValidationService service = new CaptchaValidationService(props, RestClient.create());

        assertThat(service.validateCaptcha(null, null)).isFalse();
        assertThat(service.validateCaptcha("  ", "127.0.0.1")).isFalse();
    }

    @Test
    void validatesCaptchaWithSuccessfulRemoteResponse() {
        CaptchaProps props = new CaptchaProps();
        props.setProvider(CaptchaProps.Provider.RECAPTCHA);
        props.setSecretKey("secret-value");
        props.setVerifyUrl("https://captcha.test/verify");

        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).ignoreExpectOrder(true).build();
        RestClient restClient = builder.build();

        CaptchaValidationService service = new CaptchaValidationService(props, restClient);

        MultiValueMap<String, String> expected = new LinkedMultiValueMap<>();
        expected.add("secret", "secret-value");
        expected.add("response", "token-value");
        expected.add("remoteip", "127.0.0.1");

        server.expect(requestTo(props.getVerifyUrl()))
                .andExpect(method(HttpMethod.POST))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_FORM_URLENCODED))
                .andExpect(content().formData(expected))
                .andRespond(withSuccess("{\"success\":true,\"error-codes\":[],\"hostname\":\"example.com\"}",
                        MediaType.APPLICATION_JSON));

        assertThat(service.validateCaptcha("token-value", "127.0.0.1")).isTrue();
        server.verify();
    }

    @Test
    void returnsFalseWhenRemoteResponseContainsErrors() {
        CaptchaProps props = new CaptchaProps();
        props.setProvider(CaptchaProps.Provider.RECAPTCHA);
        props.setSecretKey("secret-value");
        props.setVerifyUrl("https://captcha.test/verify");

        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        RestClient restClient = builder.build();

        CaptchaValidationService service = new CaptchaValidationService(props, restClient);

        MultiValueMap<String, String> expected = new LinkedMultiValueMap<>();
        expected.add("secret", "secret-value");
        expected.add("response", "bad-token");

        server.expect(requestTo(props.getVerifyUrl()))
                .andExpect(method(HttpMethod.POST))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_FORM_URLENCODED))
                .andExpect(content().formData(expected))
                .andRespond(
                        withSuccess("{\"success\":false,\"error-codes\":[\"invalid-input-response\",\"bad-request\"]}",
                                MediaType.APPLICATION_JSON));

        assertThat(service.validateCaptcha("bad-token", null)).isFalse();
        server.verify();
    }
}
