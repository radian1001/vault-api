package com.vaultapi.services;

import com.vaultapi.entity.SessionEntity;
import com.vaultapi.entity.UserEntity;
import com.vaultapi.repo.SessionRepo;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;

@Service
@Transactional
@RequiredArgsConstructor
public class SessionService {
    private final SessionRepo sessionRepo;
    private final JwtService jwtService;
    private static final Integer SESSION_LIMIT = 4;

    /**
     * SHA-256 hex, not bcrypt: this hash is looked up by value on every refresh, so it
     * has to be deterministic - bcrypt salts randomly and would never match itself.
     * <p>
     * Safe here because the input is an already-signed, high-entropy JWT. There is no
     * low-entropy secret to brute-force, which is the only thing bcrypt's slowness buys.
     */
    String hashToken(String refreshToken) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(refreshToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandatory on every JVM, so this branch is unreachable.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public void checkSessionLimit(List<SessionEntity> users) {
        if(users.size() > SESSION_LIMIT) {
            //deleting the LRU session
            users.sort(Comparator.comparing(SessionEntity::getLastUsedAt));
            sessionRepo.delete(users.getFirst());
            users.removeFirst();

        }
    }

    public void addRowLogin(UserEntity userEntity, String refreshToken, String deviceLabel) {
        checkSessionLimit(sessionRepo.findByUser(userEntity));
        SessionEntity sessionEntity=SessionEntity.builder()
                .tokenHash(hashToken(refreshToken))
                .user(userEntity)
                .deviceLabel(truncateDeviceLabel(deviceLabel))
                .expiresAt(jwtService.getRefreshTokenExpiryDate(refreshToken))
                .build();
        sessionRepo.save(sessionEntity);
    }

    /**
     * Raw User-Agent. Attacker-controlled and unbounded, so it is capped to the column
     * width - an oversized header must not turn a login into a 500.
     */
    private String truncateDeviceLabel(String deviceLabel) {
        if (deviceLabel == null || deviceLabel.isBlank()) {
            return "unknown";
        }
        return deviceLabel.length() <= 255 ? deviceLabel : deviceLabel.substring(0, 255);
    }

    public SessionEntity userExists(String refreshToken) {
      // BadCredentialsException, not UserNotFoundException: a revoked, rotated-away or
      // forged token is an authentication failure (401), never a 404. The message carries
      // no token - it is a live credential, and this string reaches both the response body
      // and the error log. Revoked and forged now look identical to a caller, which is the
      // point: the difference between them is not something an attacker gets to learn.
      SessionEntity sessionValidateEntity=sessionRepo.findByTokenHash(hashToken(refreshToken))
              .orElseThrow(() -> new BadCredentialsException("Invalid refresh token"));
      sessionValidateEntity.setLastUsedAt(Instant.now());
      sessionRepo.save(sessionValidateEntity);
      return sessionValidateEntity;
    }

}
