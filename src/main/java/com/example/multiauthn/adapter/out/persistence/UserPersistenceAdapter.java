package com.example.multiauthn.adapter.out.persistence;

import static java.util.stream.Collectors.toList;

import java.util.Collections;

import org.springframework.stereotype.Repository;

import com.example.multiauthn.application.port.out.UserPort;
import com.example.multiauthn.domain.UserDto;

import lombok.RequiredArgsConstructor;

@Repository
@RequiredArgsConstructor
public class UserPersistenceAdapter implements UserPort {

    private final UserJpaRepository userRepo;
    private final RoleJpaRepository roleRepo;

    @Override
    public UserDto registerNewUser(UserDto user) {
        UserJpaEntity entity = new UserJpaEntity();
        entity.setFirstName(user.getFirstName());
        entity.setLastName(user.getLastName());
        entity.setUsername(user.getUsername());
        entity.setPassword(user.getPassword());
        entity.setEmail(user.getEmail());
        entity.setRoles(Collections.singletonList(roleRepo.findByName("ROLE_USER")));
        userRepo.save(entity);
        return user;
    }

    @Override
    public UserDto findByUsername(String username) {
        UserJpaEntity userEntity = userRepo.findByUsername(username);
        if (userEntity == null) {
            return null;
        }
        return UserDto.builder()
                .username(userEntity.getUsername())
                .password(userEntity.getPassword())
                .email(userEntity.getEmail())
                .firstName(userEntity.getFirstName())
                .lastName(userEntity.getLastName())
                .roles(userEntity.getRoles().stream()
                        .map(RoleJpaEntity::getName)
                        .collect(toList()))
                .build();
    }
}
