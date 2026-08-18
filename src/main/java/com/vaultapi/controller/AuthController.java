package com.vaultapi.controller;

import com.vaultapi.dto.*;
import com.vaultapi.entity.SessionEntity;
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
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    // The name written at login is the exact name read at refresh and cleared at logout.
    // One constant so those three can never drift apart.
    private static final String REFRESH_COOKIE = "refresh_token";

    // Scoped to /auth: the refresh token is never sent to /posts or /admin, so an XSS on
    // those paths cannot reach it. Set at login, matched again when clearing at logout.
    private static final String COOKIE_PATH = "/auth";

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
        LoginResponseDto loginResponseDto=authService.login(loginDto, request.getHeader("User-Agent"));
        Cookie cookies = new Cookie(REFRESH_COOKIE, loginResponseDto.getRefreshToken());
        cookies.setHttpOnly(true);
        // Explicit, not left to the browser's default-path rule: logout has to clear this
        // cookie with the same path it was set with, and a default is not a contract.
        cookies.setPath(COOKIE_PATH);
        response.addCookie(cookies);

        return ResponseEntity.ok(loginResponseDto);
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponseDto> refresh(HttpServletRequest request,HttpServletResponse response
                                                    ){
        // An absent cookie is an authentication failure here - refresh has nothing to work with.
        String refreshToken = readRefreshCookie(request)
                .orElseThrow(() -> new AuthenticationServiceException("Refresh token not found in cookies"));
        LoginResponseDto loginResponseDto=authService.refreshToken(refreshToken);
        Cookie cookie=new Cookie(REFRESH_COOKIE, loginResponseDto.getRefreshToken());
        cookie.setHttpOnly(true);
        cookie.setPath(COOKIE_PATH);
        response.addCookie(cookie);
        return ResponseEntity.ok(loginResponseDto);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response){
        // Clearing happens either way. A caller with no cookie, or one holding a stale
        // token with no matching row, still gets 204 - logout has to be safe to call twice.
        readRefreshCookie(request).ifPresent(authService::logout);
        response.addCookie(clearedRefreshCookie());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/logout-all")
    public ResponseEntity<Void> logoutAll(@AuthenticationPrincipal UserEntity userEntity,
                                          HttpServletResponse response){
        authService.logoutAll(userEntity);
        // This device's cookie dies along with every other session.
        response.addCookie(clearedRefreshCookie());
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/sessions")
    public ResponseEntity<List<SessionResponse>> getSessions(@AuthenticationPrincipal UserEntity userEntity,
                                                            HttpServletRequest request) {
        // The caller's own refresh token is what marks one row as "this device".
        return ResponseEntity.ok(
                authService.getSessions(userEntity, readRefreshCookie(request).orElse(null)));
    }

    /**
     * getCookies() returns null - not an empty array - when the request carries no Cookie
     * header at all, so it has to be checked before streaming over it.
     */
    private Optional<String> readRefreshCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return Optional.empty();
        }
        return Arrays.stream(cookies)
                .filter(cookie -> cookie.getName().equals(REFRESH_COOKIE))
                .findFirst()
                .map(Cookie::getValue);
    }

    /**
     * Same name and path the cookie was set with at login. A browser matches a deletion on
     * both, so a mismatched path leaves the original cookie sitting in the jar.
     */
    private Cookie clearedRefreshCookie() {
        Cookie cleared = new Cookie(REFRESH_COOKIE, "");
        cleared.setHttpOnly(true);
        cleared.setPath(COOKIE_PATH);
        cleared.setMaxAge(0);
        return cleared;
    }
}
