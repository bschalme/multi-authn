package com.example.multiauthn.application.service;

import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.isA;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.example.multiauthn.application.port.out.UserPort;
import com.example.multiauthn.domain.UserDto;

@ExtendWith(MockitoExtension.class)
class MyUserDetailsServiceTest {

    private MyUserDetailsService service;

    @Mock
    private UserPort mockUserPort;

    @BeforeEach
    void setUp() {
        service = new MyUserDetailsService(mockUserPort);
    }

    @Test
    void testLoadUserByUsername() {
        // Given:
        when(mockUserPort.findByUsername(eq("fbar"))).thenReturn(UserDto.builder()
                .username("fbar")
                .password("password")
                .firstName("Foo")
                .lastName("Bar")
                .email("fbar@example.com")
                .roles(asList("ROLE_USER"))
                .build());

        // When:
        UserDetails result = service.loadUserByUsername("fbar");

        // Then:
        assertThat("UserDetails;", result, notNullValue());
        assertThat("username;", result.getUsername(), is("fbar"));
        assertThat("password;", result.getPassword(), is("password"));
        assertThat("granted authorities;", result.getAuthorities(), hasSize(1));
        assertThat("User has ROLE_USER;", result.getAuthorities().iterator().next().getAuthority(), is("ROLE_USER"));
        assertTrue(result.isEnabled(), "user is enabled;");
        assertThat("User account non-expired;", result.isAccountNonExpired(), is(true));
        assertThat("User account not locked;", result.isAccountNonLocked(), is(true));
        assertThat("User credentials not expired;", result.isCredentialsNonExpired(), is(true));
    }

    @Test
    void userNotFound() {
        // Given:
        when(mockUserPort.findByUsername(eq("noSuchUser"))).thenReturn(null);

        // When:
        Exception exception = assertThrows(UsernameNotFoundException.class, () -> {
            service.loadUserByUsername("noSuchUser");
        });

        // Then:
        assertTrue(exception.getMessage().contains("No user found with username 'noSuchUser'"));
    }
}
