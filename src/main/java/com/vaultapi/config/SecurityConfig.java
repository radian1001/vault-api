package com.vaultapi.config;

import com.vaultapi.auth.JwtAuthEntryPoint;
import com.vaultapi.auth.JwtFilterChain;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtFilterChain jwtFilterChain;
    private final JwtAuthEntryPoint  jwtAuthEntryPoint;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{
        httpSecurity.authorizeHttpRequests(
                auth-> auth
                        // Listed before /auth/** because the first match wins: these two
                        // identify the caller by access token, the rest are anonymous entry
                        // points (signup, login) or authenticate via the refresh cookie.
                        .requestMatchers("/auth/logout-all", "/auth/sessions").authenticated()
                        .requestMatchers("/auth/**").permitAll()
                        .requestMatchers("/posts/**").authenticated()
                        // denyAll, not authenticated: an endpoint we forget to configure fails closed
                        .anyRequest().denyAll()
                )
                .exceptionHandling(ex -> ex.authenticationEntryPoint(jwtAuthEntryPoint))
                .csrf(csrfConfig->csrfConfig.disable())
                .formLogin(formLogin->formLogin.disable())
                .sessionManagement(sessionConfig -> sessionConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtFilterChain, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class)
                .httpBasic(httpBasic->httpBasic.disable());
        return httpSecurity.build();
    }

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception{
        return config.getAuthenticationManager();
    }
}