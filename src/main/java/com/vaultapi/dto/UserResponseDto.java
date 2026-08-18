package com.vaultapi.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.vaultapi.dto.enums.Plans;
import com.vaultapi.dto.enums.Roles;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.Set;

/**
 * Signup/profile output. Explicit allowlist of fields safe to expose - password is
 * absent by construction, so a new sensitive column on UserEntity cannot leak here.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserResponseDto {

    private Integer id;
    private String username;
    private String email;
    @JsonIgnore
    private Set<Roles> roles;
    private Plans plans;
    private Instant planExpiration;
}
