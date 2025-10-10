package com.example.pm.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

class CaptchaPropsBindingTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(ConfigurationPropertiesAutoConfiguration.class))
            .withUserConfiguration(TestConfig.class)
            .withPropertyValues(
                    "app.auth.captcha.provider=recaptcha",
                    "app.auth.captcha.site-key=test-site",
                    "app.auth.captcha.secret-key=test-secret"
            );

    @Test
    void bindsCaptchaPropertiesIgnoringCase() {
        contextRunner.run(context -> {
            assertThat(context).hasSingleBean(CaptchaProps.class);
            CaptchaProps props = context.getBean(CaptchaProps.class);
            assertThat(props.getProvider()).isEqualTo(CaptchaProps.Provider.RECAPTCHA);
            assertThat(props.getSiteKey()).isEqualTo("test-site");
            assertThat(props.getSecretKey()).isEqualTo("test-secret");
        });
    }

    @org.springframework.context.annotation.Configuration(proxyBeanMethods = false)
    @org.springframework.boot.context.properties.EnableConfigurationProperties(CaptchaProps.class)
    static class TestConfig { }
}