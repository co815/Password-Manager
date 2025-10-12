package com.example.pm.auth;

import com.example.pm.config.CaptchaProps;
import com.example.pm.dto.AuthDtos.CaptchaConfigResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth/captcha")
public class CaptchaController {

    private final CaptchaProps captchaProps;

    public CaptchaController(CaptchaProps captchaProps) {
        this.captchaProps = captchaProps;
    }

    @GetMapping("/config")
    public CaptchaConfigResponse config() {
        boolean enabled = captchaProps.isEnabled();
        String siteKey = null;

        if (enabled) {
            if (captchaProps.getProvider() == CaptchaProps.Provider.GENERIC) {
                siteKey = sanitizePrompt(captchaProps.getSiteKey());
            } else {
                String configuredSiteKey = captchaProps.getSiteKey();
                enabled = configuredSiteKey != null && !configuredSiteKey.isBlank();
                siteKey = enabled ? configuredSiteKey : null;
            }
        }

        return new CaptchaConfigResponse(
                enabled,
                captchaProps.getProvider(),
                siteKey
        );
    }

    private String sanitizePrompt(String raw) {
        if (raw == null || raw.isBlank()) {
            return "Type the word HUMAN to verify you are not a bot.";
        }
        return raw.trim();
    }
}