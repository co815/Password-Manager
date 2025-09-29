package com.example.pm.auth;

import com.example.pm.config.EmailSenderProperties;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

@Profile("!dev & !test")
@Component
public class SmtpEmailSender implements EmailSender {

    private static final Logger log = LoggerFactory.getLogger(SmtpEmailSender.class);

    private final JavaMailSender mailSender;
    private final EmailSenderProperties properties;

    public SmtpEmailSender(JavaMailSender mailSender, EmailSenderProperties properties) {
        this.mailSender = mailSender;
        this.properties = properties;
    }

    @Override
    public void sendVerificationEmail(String email, String username, String verificationLink) {
        MimeMessage message = mailSender.createMimeMessage();
        try {
            MimeMessageHelper helper = new MimeMessageHelper(message, MimeMessageHelper.MULTIPART_MODE_MIXED_RELATED,
                    StandardCharsets.UTF_8.name());
            helper.setFrom(properties.getFrom());
            helper.setTo(email);
            helper.setSubject(formatSubject(username));
            helper.setText(formatBody(username, verificationLink), false);
            mailSender.send(message);
            log.debug("Verification email sent to {}", email);
        } catch (MessagingException ex) {
            throw new IllegalStateException("Failed to send verification email", ex);
        }
    }

    private String formatSubject(String username) {
        return String.format(resolveTemplate(properties.getSubjectTemplate()), username);
    }

    private String formatBody(String username, String verificationLink) {
        return String.format(resolveTemplate(properties.getBodyTemplate()), username, verificationLink);
    }

    private String resolveTemplate(String template) {
        return template.replace("\\n", System.lineSeparator());
    }
}