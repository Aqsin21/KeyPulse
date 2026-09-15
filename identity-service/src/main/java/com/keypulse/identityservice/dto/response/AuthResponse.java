package com.keypulse.identityservice.dto.response;

public record AuthResponse(
        String accessToken,
        String refreshToken,
        long expiresInSeconds
) {}