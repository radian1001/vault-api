package com.vaultapi.controller;

import com.vaultapi.dto.LoginDto;
import com.vaultapi.dto.LoginResponseDto;
import com.vaultapi.dto.UserRequestDto;
import com.vaultapi.dto.UserResponseDto;
import com.vaultapi.entity.UserEntity;
import com.vaultapi.services.AuthService;
import com.vaultapi.services.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final AuthService authService;
    private final ModelMapper modelMapper;

    @PostMapping("/signup")
    public ResponseEntity<UserResponseDto> signUp(@Valid @RequestBody UserRequestDto userRequestDto){
        UserEntity createdUser = userService.signUp(userRequestDto);
        UserResponseDto response = modelMapper.map(createdUser, UserResponseDto.class);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(@Valid @RequestBody LoginDto loginDto) {
        // Both tokens go in the body for M2. The refresh-token cookie is M4's job, and it
        // carries the refresh token, not the access token.
        return ResponseEntity.ok(authService.login(loginDto));
    }
}