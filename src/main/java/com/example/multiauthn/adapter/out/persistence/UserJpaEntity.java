package com.example.multiauthn.adapter.out.persistence;

import static jakarta.persistence.FetchType.EAGER;

import java.util.Collection;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.Data;

@Entity
@Table(name = "user")
@Data
public class UserJpaEntity {
    @Id
    @Column(unique = true, nullable = false)
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long userid;

    private String username;
    private String firstName;
    private String lastName;
    private String email;
    private String password;

    @OneToMany(fetch = EAGER)
    private Collection<RoleJpaEntity> roles;
}
