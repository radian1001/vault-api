package com.vaultapi.config;

import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class AppConfig {
    @Bean
    ModelMapper modelMapper() {
        // ModelMapper converts between JPA entities and DTOs for API responses.
        return new ModelMapper();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        // BCrypt stores passwords as hashes instead of plain text.
        return new BCryptPasswordEncoder();
    }
}
