package com.example.pm.security;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {

    private static final int MAX_BODY_SIZE = 16 * 1024;

    private final byte[] cachedBody;

    CachedBodyHttpServletRequest(HttpServletRequest request) throws IOException {
        super(request);
        try (var inputStream = request.getInputStream()) {
            this.cachedBody = readWithLimit(inputStream, MAX_BODY_SIZE);
        }
    }

    private byte[] readWithLimit(InputStream inputStream, int limit) throws IOException {
        byte[] buffer = new byte[limit + 1];
        int bytesRead = 0;
        int n;
        while (bytesRead < buffer.length && (n = inputStream.read(buffer, bytesRead, buffer.length - bytesRead)) != -1) {
            bytesRead += n;
        }

        if (bytesRead > limit) {
            throw new IOException("Request body too large. Max size is " + limit + " bytes.");
        }

        byte[] result = new byte[bytesRead];
        System.arraycopy(buffer, 0, result, 0, bytesRead);
        return result;
    }

    @Override
    public ServletInputStream getInputStream() {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(cachedBody);
        return new ServletInputStream() {
            @Override
            public int read() {
                return byteArrayInputStream.read();
            }

            @Override
            public boolean isFinished() {
                return byteArrayInputStream.available() == 0;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener readListener) {

            }
        };
    }

    @Override
    public BufferedReader getReader() {
        return new BufferedReader(new InputStreamReader(getInputStream(), StandardCharsets.UTF_8));
    }

    byte[] getCachedBody() {
        return cachedBody.clone();
    }
}
