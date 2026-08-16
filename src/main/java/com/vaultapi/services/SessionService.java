package com.vaultapi.services;

import com.vaultapi.entity.SessionEntity;
import com.vaultapi.entity.UserEntity;
import com.vaultapi.error.UserNotFoundException;
import com.vaultapi.repo.SessionRepo;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
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
    private String hashToken(String refreshToken) {
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

    public void addRowLogin(UserEntity userEntity, String refreshToken) {
        checkSessionLimit(sessionRepo.findByUser(userEntity));
        SessionEntity sessionEntity=SessionEntity.builder()
                .tokenHash(hashToken(refreshToken))
                .user(userEntity)
                .expiresAt(jwtService.getRefreshTokenExpiryDate(refreshToken))
                .build();
        sessionRepo.save(sessionEntity);
    }

    public SessionEntity userExists(String refreshToken) {
      SessionEntity sessionValidateEntity=sessionRepo.findByTokenHash(hashToken(refreshToken)).orElseThrow(()->new UserNotFoundException("User not found with refresh token: " + refreshToken));
      sessionValidateEntity.setLastUsedAt(Instant.now());
      sessionRepo.save(sessionValidateEntity);
      return sessionValidateEntity;
    }

}
