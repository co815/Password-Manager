package com.example.pm.auth;

import com.example.pm.config.CaptchaProps;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class CaptchaControllerTest {

    @Test
    void returnsDisabledWhenCaptchaNotConfigured() throws Exception {
        CaptchaProps props = new CaptchaProps();
        props.setProvider(CaptchaProps.Provider.NONE);
        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new CaptchaController(props)).build();

        mockMvc.perform(get("/api/auth/captcha/config"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(false))
                .andExpect(jsonPath("$.provider").value("NONE"))
                .andExpect(jsonPath("$.siteKey").value(Matchers.nullValue()));
    }

    @Test
    void returnsSiteKeyWhenCaptchaConfigured() throws Exception {
        CaptchaProps props = new CaptchaProps();
        props.setProvider(CaptchaProps.Provider.RECAPTCHA);
        props.setSiteKey("site-key-123");
        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new CaptchaController(props)).build();

        mockMvc.perform(get("/api/auth/captcha/config"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(true))
                .andExpect(jsonPath("$.provider").value("RECAPTCHA"))
                .andExpect(jsonPath("$.siteKey").value("site-key-123"));
    }

    @Test
    void returnsDefaultPromptWhenGenericCaptchaEnabled() throws Exception {
        CaptchaProps props = new CaptchaProps();
        props.setProvider(CaptchaProps.Provider.GENERIC);
        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new CaptchaController(props)).build();

        mockMvc.perform(get("/api/auth/captcha/config"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(true))
                .andExpect(jsonPath("$.provider").value("GENERIC"))
                .andExpect(jsonPath("$.siteKey").value("Type the word HUMAN to verify you are not a bot."));
    }
}