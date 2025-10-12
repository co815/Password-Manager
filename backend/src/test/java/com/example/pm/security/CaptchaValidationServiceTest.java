package com.example.pm.security;

import com.example.pm.config.CaptchaProps;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;

class CaptchaValidationServiceTest {

    @Test
    void validatesGenericCaptchaUsingSecretKey() {
        CaptchaProps props = new CaptchaProps();
        props.setProvider(CaptchaProps.Provider.GENERIC);
        props.setSecretKey("letmein");

        CaptchaValidationService service = new CaptchaValidationService(props, RestClient.create());

        assertThat(service.validateCaptcha("LETMEIN", "127.0.0.1")).isTrue();
        assertThat(service.validateCaptcha("wrong", "127.0.0.1")).isFalse();
    }

    @Test
    void fallsBackToDefaultAnswerWhenSecretMissing() {
        CaptchaProps props = new CaptchaProps();
        props.setProvider(CaptchaProps.Provider.GENERIC);
        props.setSecretKey(null);

        CaptchaValidationService service = new CaptchaValidationService(props, RestClient.create());

        assertThat(service.validateCaptcha("human", null)).isTrue();
        assertThat(service.validateCaptcha("robot", null)).isFalse();
    }
}