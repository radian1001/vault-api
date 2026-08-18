package com.vaultapi.services;

import com.vaultapi.entity.UserEntity;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {

    private final SecretKey secretKey;
    private final long accessTokenExpiryMs;
    private final long refreshTokenExpiryMs;

    // Constructor injection, not @Value on fields: the key is derived once at startup, so a
    // secret shorter than 32 bytes fails the context load instead of the first login.
    public JwtService(@Value("${jwt.secret}") String secret,
                      @Value("${jwt.access-token-expiry-ms}") long accessTokenExpiryMs,
                      @Value("${jwt.refresh-token-expiry-ms}") long refreshTokenExpiryMs) {
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenExpiryMs = accessTokenExpiryMs;
        this.refreshTokenExpiryMs = refreshTokenExpiryMs;
    }

    String generateAccessToken(UserEntity user){
        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(user.getId().toString())
                .claim("username", user.getUsername())
                .claim("roles", user.getRoles())
                .claim("tokenType", "accessToken")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + accessTokenExpiryMs))
                .signWith(secretKey)
                .compact();
    }

    String generateRefreshToken(UserEntity user){
        return Jwts.builder()
                // jti (RFC 7519), and load-bearing here rather than cosmetic: iat/exp are
                // second-granularity, so two logins inside the same second would otherwise
                // build identical claims and sign to a byte-identical token. Two devices
                // would share one credential, and the session row keyed on its hash could
                // not tell them apart - logging out one would log out the other.
                .id((UUID.randomUUID().toString()))
                .subject(user.getId().toString())
                .claim("username", user.getUsername())
                .claim("roles", user.getRoles())
                .claim("tokenType", "refreshToken")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + refreshTokenExpiryMs))
                .signWith(secretKey)
                .compact();
    }

    public Integer getUserIdFromAccessToken(String token){
        // parseSignedClaims, not parseEncryptedClaims: these are JWS (signed), not JWE (encrypted).
        Claims claims = Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
        if(!"accessToken".equals(claims.get("tokenType"))){
            throw new BadCredentialsException("Invalid token type: expected accessToekn, got refreshToken");
        }
        return Integer.parseInt(claims.getSubject());
    }

    public Integer getUserIdFromRefreshToken(String token){
        Claims claim=Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
        if(!"refreshToken".equals(claim.get("tokenType"))){
            throw new BadCredentialsException("Invalid token type: expected refreshToken, got accessToken");
        }
        return Integer.parseInt(claim.getSubject());
    }

    public Instant getRefreshTokenExpiryDate(String Token) {
        Claims claim=Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(Token)
                .getPayload();
        return claim.get("exp", Date.class).toInstant();
    }
}
