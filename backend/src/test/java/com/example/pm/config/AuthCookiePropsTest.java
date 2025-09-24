package com.example.pm.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuthCookiePropsTest {

    @Test
    void sameSiteModeFromAcceptsRelaxedForms() {
        assertEquals(AuthCookieProps.SameSiteMode.NONE, AuthCookieProps.SameSiteMode.from("none"));
        assertEquals(AuthCookieProps.SameSiteMode.NONE, AuthCookieProps.SameSiteMode.from("None"));
        assertEquals(AuthCookieProps.SameSiteMode.NONE, AuthCookieProps.SameSiteMode.from("NONE"));
        assertEquals(AuthCookieProps.SameSiteMode.LAX, AuthCookieProps.SameSiteMode.from("lax"));
        assertEquals(AuthCookieProps.SameSiteMode.STRICT, AuthCookieProps.SameSiteMode.from(null));
    }

    @Test
    void sameSiteModeFromRejectsUnknownValues() {
        assertThrows(IllegalArgumentException.class, () -> AuthCookieProps.SameSiteMode.from("invalid"));
    }
}
