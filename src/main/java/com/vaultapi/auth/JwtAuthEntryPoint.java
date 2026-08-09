package com.vaultapi.auth;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Objects;

/*
 * WHAT THIS IS
 *
 * Not a filter. It is never in the chain and is never registered with
 * addFilterBefore. It is a callback, wired in SecurityConfig via
 *     .exceptionHandling(ex -> ex.authenticationEntryPoint(jwtAuthEntryPoint))
 *
 * WHO CALLS IT
 *
 * AuthorizationFilter rejects an unauthenticated request. That rejection
 * travels back up to ExceptionTranslationFilter, which DOES have a
 * try/catch. It sees the user is anonymous - "I don't know who you are"
 * rather than "you're not allowed" - and calls this.
 *
 * Its sibling is accessDeniedHandler: that one runs when the user IS known
 * but lacks permission (403). This one is the unknown-user case (401).
 *
 * WHY IT EXISTS AT ALL
 *
 * Without it, Spring uses a default. With both formLogin and httpBasic
 * disabled, that default is Http403ForbiddenEntryPoint - an empty 403 with
 * no body. The client can't tell "expired, go refresh" from "no token, go
 * log in", so it guesses wrong and logs users out every 15 minutes.
 *
 * DIVISION OF LABOUR
 *
 * JwtFilterChain decides WHAT went wrong and leaves a note.
 * This class decides what the RESPONSE looks like.
 * One place in the whole app formats a 401 - here.
 */
@Component
public class JwtAuthEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException)
            throws IOException, ServletException {

        /*
         * The note JwtFilterChain left via request.setAttribute earlier in
         * this same request. Same HttpServletRequest object: the filter reads
         * the Authorization HEADER (what the client sent), this reads an
         * ATTRIBUTE (what our own filter wrote). Attributes live for one
         * request only - nothing leaks between requests.
         */
        Object errorCheck = request.getAttribute("jwtError");

        /*
         * Null means the filter never left a note, i.e. there was no
         * Authorization header at all - the request never entered the try
         * block. Different situation, different message:
         *   "Token expired"        -> client should call /auth/refresh
         *   "Unauthorized"         -> client should send the user to login
         */
        String message = Objects.nonNull(errorCheck) ? errorCheck.toString() : "Unauthorized";

        /*
         * Written by hand rather than returned as an object: we are outside
         * DispatcherServlet here, so there is no @RestControllerAdvice, no
         * ResponseEntity, no automatic Jackson serialisation. Nothing below
         * this layer ever ran. The raw response is all we have.
         */
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"" + message + "\"}");
    }
}