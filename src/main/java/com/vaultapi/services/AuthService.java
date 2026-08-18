package com.vaultapi.services;

import com.vaultapi.dto.LoginDto;
import com.vaultapi.dto.LoginResponseDto;
import com.vaultapi.dto.SessionResponse;
import com.vaultapi.entity.SessionEntity;
import com.vaultapi.entity.UserEntity;
import com.vaultapi.repo.SessionRepo;
import jakarta.annotation.Nonnull;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

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
    private final SessionRepo sessionRepo;
    private final SessionService sessionService;
    private final ModelMapper modelMapper;

    public LoginResponseDto login(@Nonnull LoginDto loginDto, String deviceLabel) {
        // authenticate() is the only DB read: it calls loadUserByUsername internally and
        // throws BadCredentialsException / UsernameNotFoundException, both mapped to 401.
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword())
        );
        UserEntity user = (UserEntity) authentication.getPrincipal();
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);
        sessionService.addRowLogin(user, refreshToken, deviceLabel);
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

    @Transactional
    public void logout(String refreshToken) {
        sessionRepo.deleteByTokenHash(sessionService.hashToken(refreshToken));
    }

    @Transactional
    public void logoutAll(UserEntity userEntity) {
        sessionRepo.deleteByUser(userEntity);
    }

    /**
     * currentRefreshToken is the caller's own cookie, or null when they authenticated with
     * an access token alone. Hashing it once and comparing against the stored hashes is what
     * lets the response say which row is "this device" without ever echoing a token back.
     */
    @Transactional
    public List<SessionResponse> getSessions(UserEntity userEntity, String currentRefreshToken) {
        String currentHash = currentRefreshToken == null
                ? null
                : sessionService.hashToken(currentRefreshToken);

        return sessionRepo.findByUser(userEntity).stream()
                .map(sessionEntity -> {
                    SessionResponse session = modelMapper.map(sessionEntity, SessionResponse.class);
                    session.setCurrent(sessionEntity.getTokenHash().equals(currentHash));
                    return session;
                })
                .collect(Collectors.toList());
    }
}
