package com.example.pm.security;

import com.example.pm.config.CaptchaProps;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.util.List;
import java.util.Objects;

@Service
public class CaptchaValidationService {

    private static final Logger log = LoggerFactory.getLogger(CaptchaValidationService.class);

    private final CaptchaProps captchaProps;
    private final RestClient restClient;

    @Autowired
    public CaptchaValidationService(CaptchaProps captchaProps) {
        this(captchaProps, RestClient.create());
    }

    CaptchaValidationService(CaptchaProps captchaProps, RestClient restClient) {
        this.captchaProps = Objects.requireNonNull(captchaProps, "captchaProps");
        this.restClient = Objects.requireNonNull(restClient, "restClient");
    }

    public boolean validateCaptcha(String token, String remoteIp) {
        if (!captchaProps.isEnabled()) {
            return true;
        }

        if (captchaProps.getSecretKey() == null || captchaProps.getSecretKey().isBlank()) {
            log.warn("Captcha provider {} enabled without secret key", captchaProps.getProvider());
            return false;
        }

        if (token == null || token.isBlank()) {
            return false;
        }

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("secret", captchaProps.getSecretKey());
        body.add("response", token);
        if (remoteIp != null && !remoteIp.isBlank()) {
            body.add("remoteip", remoteIp);
        }

        try {
            CaptchaResponse response = restClient.post()
                    .uri(captchaProps.getVerifyUrl())
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(body)
                    .retrieve()
                    .body(CaptchaResponse.class);
            return response != null && response.success();
        } catch (RestClientException ex) {
            log.warn("Captcha validation failed: {}", ex.getMessage());
            return false;
        }
    }

    record CaptchaResponse(boolean success, List<String> errorCodes) {
    }
}