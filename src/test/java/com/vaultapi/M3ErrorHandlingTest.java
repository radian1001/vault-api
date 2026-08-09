package com.vaultapi;

import com.vaultapi.dto.enums.Plans;
import com.vaultapi.dto.enums.Roles;
import com.vaultapi.entity.UserEntity;
import com.vaultapi.repo.UserRepo;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * Verification harness for M3's done-check. No database: JPA autoconfiguration is
 * excluded and UserRepo is mocked, so this exercises the security filter chain only.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "jwt.secret=" + M3ErrorHandlingTest.SECRET,
        "jwt.access-token-expiry-ms=900000",
        "jwt.refresh-token-expiry-ms=604800000",
        "spring.autoconfigure.exclude="
                + "org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration,"
                + "org.springframework.boot.autoconfigure.jdbc.DataSourceTransactionManagerAutoConfiguration,"
                + "org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration,"
                + "org.springframework.boot.autoconfigure.data.jpa.JpaRepositoriesAutoConfiguration"
})
class M3ErrorHandlingTest {

    static final String SECRET = "local-test-secret-at-least-32-bytes-long";
    private static final SecretKey KEY = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));

    @Autowired
    private MockMvc mvc;

    @MockitoBean
    private UserRepo userRepo;

    private UserEntity user;

    @BeforeEach
    void setUp() {
        user = new UserEntity();
        user.setId(1);
        user.setUsername("alice");
        user.setPassword("{bcrypt}irrelevant");
        user.setEmail("alice@example.com");
        user.setRoles(Set.of(Roles.USER));
        user.setPlans(Plans.FREE);
    }

    private static String token(long expiryOffsetMs) {
        return Jwts.builder()
                .subject("1")
                .issuedAt(new Date(System.currentTimeMillis() - 60_000))
                .expiration(new Date(System.currentTimeMillis() + expiryOffsetMs))
                .signWith(KEY)
                .compact();
    }

    private void report(String label, MvcResult result) throws Exception {
        System.out.println("[M3] " + label
                + " -> status=" + result.getResponse().getStatus()
                + " contentType=" + result.getResponse().getContentType()
                + " body=" + result.getResponse().getContentAsString());
    }

    @Test
    void noToken() throws Exception {
        MvcResult r = mvc.perform(get("/posts")).andReturn();
        report("no token", r);
        assertThat(r.getResponse().getStatus()).isEqualTo(401);
    }

    @Test
    void malformedToken() throws Exception {
        MvcResult r = mvc.perform(get("/posts").header("Authorization", "Bearer not-a-jwt")).andReturn();
        report("malformed token", r);
        assertThat(r.getResponse().getStatus()).isEqualTo(401);
    }

    @Test
    void expiredToken() throws Exception {
        MvcResult r = mvc.perform(get("/posts").header("Authorization", "Bearer " + token(-60_000))).andReturn();
        report("expired token", r);
        assertThat(r.getResponse().getStatus()).isEqualTo(401);
        assertThat(r.getResponse().getContentAsString()).contains("Access token expired");
    }

    @Test
    void tamperedSignature() throws Exception {
        String good = token(900_000);
        String tampered = good.substring(0, good.lastIndexOf('.') + 1) + "AAAAdeadbeefAAAA";
        MvcResult r = mvc.perform(get("/posts").header("Authorization", "Bearer " + tampered)).andReturn();
        report("tampered signature", r);
        assertThat(r.getResponse().getStatus()).isEqualTo(401);
    }

    @Test
    void validTokenButUserDeleted() throws Exception {
        when(userRepo.findById(anyInt())).thenReturn(Optional.empty());
        MvcResult r = mvc.perform(get("/posts").header("Authorization", "Bearer " + token(900_000))).andReturn();
        report("valid token, user deleted", r);
        assertThat(r.getResponse().getStatus()).isEqualTo(401);
    }

    @Test
    void validToken() throws Exception {
        when(userRepo.findById(anyInt())).thenReturn(Optional.of(user));
        MvcResult r = mvc.perform(get("/posts").header("Authorization", "Bearer " + token(900_000))).andReturn();
        report("valid token", r);
    }

    @Test
    void authenticatedHittingDenyAllPath() throws Exception {
        when(userRepo.findById(anyInt())).thenReturn(Optional.of(user));
        MvcResult r = mvc.perform(get("/admin/users").header("Authorization", "Bearer " + token(900_000))).andReturn();
        report("authenticated on denyAll path (403 case)", r);
    }
}
