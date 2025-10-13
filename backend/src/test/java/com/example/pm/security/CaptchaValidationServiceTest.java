package com.example.pm.security;

import com.example.pm.config.CaptchaProps;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;

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
}
