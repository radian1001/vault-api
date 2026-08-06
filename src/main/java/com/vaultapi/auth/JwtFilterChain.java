package com.vaultapi.auth;

import com.vaultapi.entity.UserEntity;
import com.vaultapi.repo.UserRepo;
import com.vaultapi.services.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
//this is for adding the new filterchain just above the usernameandpasswordfilterchain
public class JwtFilterChain extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserRepo userRepo;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorization=request.getHeader("Authorization");
        if(authorization==null || !authorization.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            return;
        }
        String token=authorization.substring(7);
        Integer userId=jwtService.getUserIdFromToken(token);

        if(userId!=null && SecurityContextHolder.getContext().getAuthentication()==null){
            UserEntity userEntity=userRepo.findById(userId).orElseThrow(() -> new RuntimeException("User id is not there"));
            // The 3-arg constructor is the authenticated form. The signature check above is the
            // authentication, so there is nothing left for AuthenticationManager to verify.
            UsernamePasswordAuthenticationToken authentication=new UsernamePasswordAuthenticationToken(userEntity,null,userEntity.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);

        }
        filterChain.doFilter(request,response);


    }
}
