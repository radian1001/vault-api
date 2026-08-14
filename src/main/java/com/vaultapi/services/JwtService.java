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
import java.util.Date;

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

}
