package com.vaultapi.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SessionResponse {
    Integer id;
    UserResponseDto user;
    String deviceLabel;
    Instant lastUsedAt;
    Instant expiresAt;
    boolean current;
}
