package com.vaultapi.auth;

import com.vaultapi.entity.UserEntity;
import com.vaultapi.repo.UserRepo;
import com.vaultapi.services.JwtService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
//this is for adding the new filterchain just above the usernameandpasswordfilterchain


/*
 * WHERE THIS SITS
 *
 * Filters are nested method calls, not a queue. Each one calls into the next:
 *
 *   FilterChainProxy
 *    └── SecurityContextHolderFilter
 *         └── JwtFilterChain            <-- this class
 *              └── AnonymousAuthenticationFilter
 *                   └── ExceptionTranslationFilter
 *                        └── AuthorizationFilter
 *                             └── DispatcherServlet
 *                                  └── controller
 *
 * Consequence: an exception thrown here travels UP, away from everything
 * listed below. ExceptionTranslationFilter can't catch it (its try block
 * hasn't started). @RestControllerAdvice can't see it (DispatcherServlet
 * never ran). It escapes to Tomcat -> 500.
 *
 * So this filter must never let an exception escape.
 *
 * THIS FILTER'S ONLY JOB: if a valid token is present, put the user in the
 * SecurityContext. It never rejects anyone. Rejecting is AuthorizationFilter's
 * job, and it already does it for every request.
 */
public class JwtFilterChain extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserRepo userRepo;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorization=request.getHeader("Authorization");


        // No token at all. Not an error - could be /auth/login, which is permitAll.
        // Continue with nobody authenticated and let the rules decide.
        if(authorization==null || !authorization.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            return;
        }
        String token=authorization.substring(7);


//        if(userId!=null && SecurityContextHolder.getContext().getAuthentication()==null){
//            UserEntity userEntity=userRepo.findById(userId).orElseThrow(() -> new UserNotFoundException("User id is not there"));
//            // The 3-arg constructor is the authenticated form. The signature check above is the
//            // authentication, so there is nothing left for AuthenticationManager to verify.
//            UsernamePasswordAuthenticationToken authentication=new UsernamePasswordAuthenticationToken(userEntity,null,userEntity.getAuthorities());
//            SecurityContextHolder.getContext().setAuthentication(authentication);
//
//        }
//        filterChain.doFilter(request,response);


        /*
         * Only token parsing goes inside the try.
         * filterChain.doFilter is deliberately NOT in here: it opens every
         * deeper filter, the servlet and the controller, so any exception
         * from your service layer would land in these catch blocks. That
         * layer belongs to @RestControllerAdvice, not to this filter.
         */
        try{
            Integer userId=jwtService.getUserIdFromAccessToken(token);
            if(userId!=null && SecurityContextHolder.getContext().getAuthentication()==null) {
                UserEntity userEntity = userRepo.findById(userId).orElse(null);

                // Token signature was valid but the user is gone (deleted account).
                // Vague message on purpose - "user not found" would tell an attacker
                // which ids exist. Detail goes to the log, not the response.
                if (userEntity == null) {
                    request.setAttribute("jwtError", "User not found");
                    SecurityContextHolder.clearContext();
                } else {

                    // 3-arg constructor = already authenticated. The signature check
                    // above WAS the authentication; AuthenticationManager has nothing
                    // left to verify.
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userEntity, null, userEntity.getAuthorities());
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        } catch (ExpiredJwtException e) {
            request.setAttribute("jwtError","Access token expired");
            SecurityContextHolder.clearContext();
        } catch (IllegalArgumentException | JwtException | BadCredentialsException e) {
            request.setAttribute("jwtError", "Invalid access token");
            SecurityContextHolder.clearContext();
        }
        /*
         * Runs no matter what happened above - exactly once.
         *
         * Continuing with a bad token is safe: the SecurityContext is empty,
         * so AuthorizationFilter denies the request, ExceptionTranslationFilter
         * sees an anonymous user and calls JwtAuthEntryPoint, which reads the
         * "jwtError" note and writes the 401 JSON.
         *
         * This is also why /auth/refresh works. permitAll is an AUTHORIZATION
         * rule - this filter still runs on that path. Clients keep sending the
         * expired Authorization header automatically. Without the catch above,
         * refresh would 500 exactly when it's needed.
         *
         * setAttribute is a scratchpad living for this one request only:
         * filter decides WHAT went wrong, entry point decides what the
         * RESPONSE looks like.
         */
        filterChain.doFilter(request,response);


    }
}
