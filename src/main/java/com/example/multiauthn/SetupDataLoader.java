package com.example.multiauthn;

import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;

import com.example.multiauthn.adapter.out.persistence.RoleJpaEntity;
import com.example.multiauthn.adapter.out.persistence.RoleJpaRepository;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class SetupDataLoader implements ApplicationListener<ContextRefreshedEvent> {
    private final RoleJpaRepository roleRepository;

    private boolean alreadySetup = false;

    @Override
    @Transactional
    public void onApplicationEvent(@NonNull ContextRefreshedEvent event) {
        if (alreadySetup) {
            return;
        }
        createRoleIfNotFound("ROLE_USER");

        alreadySetup = true;
    }
    public RoleJpaEntity createRoleIfNotFound(final String name) {
        RoleJpaEntity role = roleRepository.findByName(name);
        if (role == null) {
            role = new RoleJpaEntity();
            role.setName(name);
        }
        role = roleRepository.save(role);
        return role;
    }

}
