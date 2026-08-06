package com.vaultapi.services;

import com.vaultapi.dto.LoginDto;
import com.vaultapi.dto.LoginResponseDto;
import com.vaultapi.entity.UserEntity;
import jakarta.annotation.Nonnull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

/**
 * Holds AuthenticationManager so UserService does not have to.
 * <p>
 * UserService is the UserDetailsService bean. AuthenticationManager is built from that
 * same bean, so injecting the manager back into UserService is a cycle Spring cannot
 * resolve: UserService -> AuthenticationManager -> AuthenticationConfiguration -> UserService.
 * Keeping the manager in a separate bean breaks it.
 */
@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    public LoginResponseDto login(@Nonnull LoginDto loginDto) {
        // authenticate() is the only DB read: it calls loadUserByUsername internally and
        // throws BadCredentialsException / UsernameNotFoundException, both mapped to 401.
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword())
        );
        UserEntity user = (UserEntity) authentication.getPrincipal();
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);
        return new LoginResponseDto(user.getId(), accessToken, refreshToken);
    }


}
