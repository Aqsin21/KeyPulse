package com.keypulse.identityservice.service;

import com.keypulse.identityservice.dto.request.LoginRequest;
import com.keypulse.identityservice.dto.request.RefreshTokenRequest;
import com.keypulse.identityservice.dto.request.RegisterRequest;
import com.keypulse.identityservice.dto.response.AuthResponse;
import com.keypulse.identityservice.entity.User;
import com.keypulse.identityservice.exception.EmailAlreadyExistsException;
import com.keypulse.identityservice.exception.InvalidCredentialsException;
import com.keypulse.identityservice.exception.InvalidTokenException;
import com.keypulse.identityservice.repository.UserRepository;
import com.keypulse.identityservice.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new EmailAlreadyExistsException("Email already registered: " + request.email());
        }

        User user = User.builder()
                .email(request.email())
                .passwordHash(passwordEncoder.encode(request.password()))
                .fullName(request.fullName())
                .role(User.Role.USER)
                .build();

        userRepository.save(user);

        return buildAuthResponse(user);
    }

    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new InvalidCredentialsException("Invalid email or password"));

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw new InvalidCredentialsException("Invalid email or password");
        }

        return buildAuthResponse(user);
    }

    private AuthResponse buildAuthResponse(User user) {
        String accessToken = jwtService.generateAccessToken(user.getId(), user.getEmail(), user.getRole().name());
        String refreshToken = jwtService.generateRefreshToken(user.getId());
        return new AuthResponse(accessToken, refreshToken, jwtService.getAccessTokenExpirationSeconds());
    }
    public AuthResponse refresh(RefreshTokenRequest request) {
        String token = request.refreshToken();

        if (!jwtService.isTokenValid(token)) {
            throw new InvalidTokenException("Refresh token is invalid or expired");
        }

        if (!"refresh".equals(jwtService.extractTokenType(token))) {
            throw new InvalidTokenException("Provided token is not a refresh token");
        }

        UUID userId = jwtService.extractUserId(token);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new InvalidTokenException("User no longer exists"));

        return buildAuthResponse(user);
    }
}