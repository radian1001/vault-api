package com.vaultapi.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;

/**
 * One row per live refresh token, which is what makes a stateless JWT revocable.
 * <p>
 * The JWT itself can never be taken back once signed - it stays valid until its exp.
 * Requiring a matching row here adds the missing "and we still allow this one" check,
 * so deleting the row kills the token immediately (M5's done-check).
 */
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Data
@Builder
@Table(indexes = @Index(name = "idx_session_token_hash", columnList = "tokenHash", unique = true))
public class SessionEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    /**
     * SHA-256 of the refresh token, never the token itself (constraint 2). A leaked
     * database dump must not hand out working tokens.
     * <p>
     * Plain SHA-256, not bcrypt: the input is already signed high-entropy data, so
     * there is nothing to brute-force, and this is looked up by value on every
     * refresh - it has to be deterministic.
     * <p>
     * 64 chars = SHA-256 rendered as hex.
     */
    @Column(nullable = false, unique = true, length = 64)
    private String tokenHash;


    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private UserEntity user;

    // Which device this session belongs to, so GET /auth/sessions is readable and
    // M8's LRU eviction can name what it dropped.
    private String deviceLabel;


    // Hibernate stamps this on insert and on every update, so refreshing a token
    // touches it for free. M8 sorts by this column to pick the eviction victim.
    @UpdateTimestamp
    @Column(nullable = false)
    private Instant lastUsedAt;

    // Mirrors the refresh token's exp claim. Redundant with the JWT on purpose:
    // it lets expired rows be swept without parsing every token.
    @Column(nullable = false)
    private Instant expiresAt;
}
