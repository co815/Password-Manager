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
        boolean enabled = captchaProps.isEnabled()
                && captchaProps.getSiteKey() != null
                && !captchaProps.getSiteKey().isBlank();
        String siteKey = enabled ? captchaProps.getSiteKey() : null;
        return new CaptchaConfigResponse(
                enabled,
                captchaProps.getProvider(),
                siteKey
        );
    }
}