package com.example.pm.config;

import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.core.convert.converter.Converter;
import org.springframework.stereotype.Component;

@Component
@ConfigurationPropertiesBinding
public class SameSiteModeConverter implements Converter<String, AuthCookieProps.SameSiteMode> {

    @Override
    public AuthCookieProps.SameSiteMode convert(String source) {
        return AuthCookieProps.SameSiteMode.from(source);
    }
}