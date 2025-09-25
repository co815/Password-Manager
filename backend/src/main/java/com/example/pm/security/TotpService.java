package com.example.pm.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

@Service
public class TotpService {

    private static final char[] BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();
    private static final int SECRET_SIZE = 20; // 160 bits
    private static final int TOTP_DIGITS = 6;
    private static final int TIME_STEP_SECONDS = 30;
    private static final int WINDOW = 1;

    private final SecureRandom secureRandom = new SecureRandom();
    private final String issuer;

    public TotpService(@Value("${app.mfa.issuer:PasswordManager}") String issuer) {
        this.issuer = issuer;
    }

    public String generateSecret() {
        byte[] buffer = new byte[SECRET_SIZE];
        secureRandom.nextBytes(buffer);
        return encodeBase32(buffer);
    }

    public String buildOtpAuthUrl(String accountName, String secret) {
        String label = issuer + ":" + (accountName == null ? "user" : accountName);
        String encodedLabel = urlEncode(label);
        String encodedIssuer = urlEncode(issuer);
        return "otpauth://totp/" + encodedLabel
                + "?secret=" + secret
                + "&issuer=" + encodedIssuer
                + "&digits=" + TOTP_DIGITS
                + "&period=" + TIME_STEP_SECONDS;
    }

    public boolean verifyCode(String secret, String code) {
        if (secret == null || secret.isBlank() || code == null) {
            return false;
        }
        String trimmed = code.trim();
        if (!trimmed.matches("\\d{" + TOTP_DIGITS + "}")) {
            return false;
        }
        byte[] key;
        try {
            key = decodeBase32(secret);
        } catch (IllegalArgumentException ex) {
            return false;
        }
        long currentInterval = Instant.now().getEpochSecond() / TIME_STEP_SECONDS;
        for (int offset = -WINDOW; offset <= WINDOW; offset++) {
            long counter = currentInterval + offset;
            if (counter < 0) {
                continue;
            }
            int expected = generateTotp(key, counter);
            if (timedEquals(expected, Integer.parseInt(trimmed))) {
                return true;
            }
        }
        return false;
    }

    private int generateTotp(byte[] key, long counter) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] data = ByteBuffer.allocate(8).putLong(counter).array();
            byte[] hash = mac.doFinal(data);

            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7f) << 24)
                    | ((hash[offset + 1] & 0xff) << 16)
                    | ((hash[offset + 2] & 0xff) << 8)
                    | (hash[offset + 3] & 0xff);
            int otp = binary % (int) Math.pow(10, TOTP_DIGITS);
            return otp;
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Failed to generate TOTP", ex);
        }
    }

    private boolean timedEquals(int a, int b) {
        byte[] left = ByteBuffer.allocate(Integer.BYTES).putInt(a).array();
        byte[] right = ByteBuffer.allocate(Integer.BYTES).putInt(b).array();
        return MessageDigest.isEqual(left, right);
    }

    private String encodeBase32(byte[] data) {
        StringBuilder sb = new StringBuilder((data.length * 8 + 4) / 5);
        int buffer = 0;
        int bitsLeft = 0;
        for (byte value : data) {
            buffer = (buffer << 8) | (value & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                int index = (buffer >> (bitsLeft - 5)) & 0x1F;
                bitsLeft -= 5;
                sb.append(BASE32_ALPHABET[index]);
            }
        }
        if (bitsLeft > 0) {
            int index = (buffer << (5 - bitsLeft)) & 0x1F;
            sb.append(BASE32_ALPHABET[index]);
        }
        return sb.toString();
    }

    private byte[] decodeBase32(String secret) {
        String normalized = secret.trim().toUpperCase(Locale.ROOT).replace("=", "");
        List<Byte> bytes = new ArrayList<>();
        int buffer = 0;
        int bitsLeft = 0;
        for (char c : normalized.toCharArray()) {
            int value = indexOfBase32(c);
            if (value < 0) {
                throw new IllegalArgumentException("Invalid base32 character: " + c);
            }
            buffer = (buffer << 5) | value;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                int byteValue = (buffer >> (bitsLeft - 8)) & 0xFF;
                bitsLeft -= 8;
                bytes.add((byte) byteValue);
            }
        }
        byte[] result = new byte[bytes.size()];
        for (int i = 0; i < bytes.size(); i++) {
            result[i] = bytes.get(i);
        }
        return result;
    }

    private int indexOfBase32(char c) {
        for (int i = 0; i < BASE32_ALPHABET.length; i++) {
            if (BASE32_ALPHABET[i] == c) {
                return i;
            }
        }
        return -1;
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}