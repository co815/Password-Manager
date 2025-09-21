package com.example.pm.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SameSiteModeConverterTest {

    private final SameSiteModeConverter converter = new SameSiteModeConverter();

    @Test
    void convertsRelaxedValues() {
        assertEquals(AuthCookieProps.SameSiteMode.NONE, converter.convert("none"));
        assertEquals(AuthCookieProps.SameSiteMode.NONE, converter.convert("None"));
        assertEquals(AuthCookieProps.SameSiteMode.LAX, converter.convert("lax"));
    }
}