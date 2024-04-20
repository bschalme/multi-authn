package com.example.multiauthn.adapter.out.persistence;

import org.springframework.data.repository.CrudRepository;

public interface RoleJpaRepository extends CrudRepository<RoleJpaEntity, Long> {
    RoleJpaEntity findByName(String name);

}
