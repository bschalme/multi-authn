package com.example.multiauthn.adapter.out.persistence;

import java.util.Collection;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import lombok.Data;

@Entity
@Table(name = "role")
@Data
public class RoleJpaEntity {

    @Id
    @Column(unique = true, nullable = false)
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long roleId;

    @ManyToMany(mappedBy = "roles")
    private Collection<UserJpaEntity> users;

    private String name;
}
