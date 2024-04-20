package com.example.multiauthn.adapter.out.persistence;

import org.springframework.data.repository.CrudRepository;

public interface UserJpaRepository extends CrudRepository<UserJpaEntity, Long> {
    UserJpaEntity findByUsername(String username);
}
