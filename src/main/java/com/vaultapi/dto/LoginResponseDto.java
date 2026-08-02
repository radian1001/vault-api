package com.vaultapi.dto;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginResponseDto {
    private long id;
    private String accessToken;
    private String refreshToken;


}