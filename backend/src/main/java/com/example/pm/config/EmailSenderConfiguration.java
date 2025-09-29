package com.example.pm.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import java.util.Properties;

@Configuration
public class EmailSenderConfiguration {

    @Bean
    @Profile("!dev & !test")
    public JavaMailSender javaMailSender(EmailSenderProperties properties) {
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost(properties.getHost());
        mailSender.setPort(properties.getPort());
        mailSender.setUsername(properties.getUsername());
        mailSender.setPassword(properties.getPassword());

        Properties javaMailProps = mailSender.getJavaMailProperties();
        javaMailProps.put("mail.transport.protocol", "smtp");
        javaMailProps.put("mail.smtp.auth", Boolean.toString(properties.isAuth()));
        javaMailProps.put("mail.smtp.starttls.enable", Boolean.toString(properties.isStartTls()));
        javaMailProps.put("mail.smtp.connectiontimeout", "5000");
        javaMailProps.put("mail.smtp.timeout", "5000");
        javaMailProps.put("mail.smtp.writetimeout", "5000");
        return mailSender;
    }
}