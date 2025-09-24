package com.example.pm.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import static org.assertj.core.api.Assertions.assertThat;

class AuthCookiePropsBindingTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(ConfigurationPropertiesAutoConfiguration.class))
            .withUserConfiguration(TestConfig.class)
            .withPropertyValues("app.auth.cookie.sameSite=None");

    @Test
    void bindsSameSiteModeFromApplicationYaml() {
        contextRunner.run(context -> {
            assertThat(context).hasSingleBean(AuthCookieProps.class);
            AuthCookieProps props = context.getBean(AuthCookieProps.class);
            assertThat(props.getSameSite()).isEqualTo(AuthCookieProps.SameSiteMode.NONE);
            assertThat(props.getSameSiteAttribute()).isEqualTo("None");
        });
    }

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(AuthCookieProps.class)
    @Import(SameSiteModeConverter.class)
    static class TestConfig { }
}
