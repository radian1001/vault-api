package com.vaultapi.repo;

import com.vaultapi.entity.SessionEntity;
import com.vaultapi.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface SessionRepo extends JpaRepository<SessionEntity, Integer> {
    List<SessionEntity> findByUser(UserEntity userEntity);

    Optional<SessionEntity> findByTokenHash(String refreshToken);

    void deleteByTokenHash(String s);

    void deleteByUser(UserEntity userEntity);
}
