package com.vaultapi.services;

import com.vaultapi.dto.LoginDto;
import com.vaultapi.dto.LoginResponseDto;
import com.vaultapi.entity.SessionEntity;
import com.vaultapi.entity.UserEntity;
import com.vaultapi.repo.UserRepo;
import jakarta.annotation.Nonnull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
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
    private final UserRepo userRepo;
    private final SessionService sessionService;

    public LoginResponseDto login(@Nonnull LoginDto loginDto) {
        // authenticate() is the only DB read: it calls loadUserByUsername internally and
        // throws BadCredentialsException / UsernameNotFoundException, both mapped to 401.
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword())
        );
        UserEntity user = (UserEntity) authentication.getPrincipal();
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);
        sessionService.addRowLogin(user,refreshToken);
        return new LoginResponseDto(user.getId(), accessToken, refreshToken);
    }



    public LoginResponseDto refreshToken(String refreshToken) {
        // Implementation for refreshing token
        Integer userId= jwtService.getUserIdFromRefreshToken(refreshToken);
        SessionEntity sessionEntity=sessionService.userExists(refreshToken);
        UserEntity userEntity=sessionEntity.getUser();
        if(!userEntity.getId().equals(userId)){
            throw new AuthenticationServiceException("Refresh token does not match user");
        }
        String accessToken = jwtService.generateAccessToken(userEntity);
        return new LoginResponseDto(userEntity.getId(), accessToken, refreshToken);
    }
}
