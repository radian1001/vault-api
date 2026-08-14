package com.vaultapi.controller;

import com.vaultapi.dto.LoginDto;
import com.vaultapi.dto.LoginResponseDto;
import com.vaultapi.dto.UserRequestDto;
import com.vaultapi.dto.UserResponseDto;
import com.vaultapi.entity.UserEntity;
import com.vaultapi.services.AuthService;
import com.vaultapi.services.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;

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
    public ResponseEntity<LoginResponseDto> login(@Valid @RequestBody LoginDto loginDto, HttpServletRequest  request, HttpServletResponse response ) {
        // Both tokens go in the body for M2. The refresh-token cookie is M4's job, and it
        // carries the refresh token, not the access token.
        LoginResponseDto loginResponseDto=authService.login(loginDto);
        Cookie cookies = new Cookie("refresh_token",loginResponseDto.getRefreshToken());
        cookies.setHttpOnly(true);
        response.addCookie(cookies);

        return ResponseEntity.ok(loginResponseDto);
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponseDto> refresh(HttpServletResponse response,HttpServletRequest request){
         Cookie[] cookies = request.getCookies();
        String refreshToken = Arrays.stream(cookies).filter(cookie -> cookie.getName().equals("refresh_token"))
                .findFirst()
                .map(Cookie::getValue)
                .orElseThrow(() -> new AuthenticationServiceException("Refresh token not found in cookies"));
        LoginResponseDto token = authService.refreshToken(refreshToken);

        return ResponseEntity.ok(token);
    }
}