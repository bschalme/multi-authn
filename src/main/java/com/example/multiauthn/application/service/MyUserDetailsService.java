package com.example.multiauthn.application.service;

import static java.lang.String.format;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.example.multiauthn.application.port.out.UserPort;
import com.example.multiauthn.domain.UserDto;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class MyUserDetailsService implements UserDetailsService {

    private final UserPort userPort;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDto userDto = userPort.findByUsername(username);
        if (userDto == null) {
            throw new UsernameNotFoundException(format("No user found with username '%s'", username));
        }
        boolean enabled = true;
        boolean accountNonExpired = true;
        boolean credentialsNonExpired = true;
        boolean accountNonLocked = true;
        return User.builder()
                .username(username)
                .password(userDto.getPassword())
                .disabled(!enabled)
                .accountExpired(!accountNonExpired)
                .credentialsExpired(!credentialsNonExpired)
                .accountLocked(!accountNonLocked)
                .authorities(getAuthorities(userDto.getRoles()))
                .build();
    }

    private List<GrantedAuthority> getAuthorities (List<String> roles) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        for (String role : roles) {
            authorities.add(new SimpleGrantedAuthority(role));
        }
        return authorities;
    }
}
