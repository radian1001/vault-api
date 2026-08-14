package com.vaultapi.controller;

import com.vaultapi.entity.UserEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Placeholder for M2's done-check: /posts must be 401 without a token and 200 with one.
 * PostEntity and real persistence arrive in a later milestone.
 */
@RestController
@RequestMapping("/posts")
@RequiredArgsConstructor
public class PostController {

    @GetMapping
    public ResponseEntity<List<String>> list(@AuthenticationPrincipal UserEntity user) {
        // Principal is the UserEntity the filter put in the context, which is what proves
        // the filter ran and populated SecurityContextHolder correctly.
        return ResponseEntity.ok(List.of("placeholder post visible to " + user.getUsername()));
    }
}
