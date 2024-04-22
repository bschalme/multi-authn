package com.example.multiauthn.adapter.out.persistence;

import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.example.multiauthn.domain.UserDto;

@ExtendWith(MockitoExtension.class)
class UserPersistenceAdapterTest {

    @InjectMocks
    private UserPersistenceAdapter adapter;

    @Mock
    private UserJpaRepository mockUserRepo;

    @Mock
    private RoleJpaRepository mockRoleRepo;

    @Captor
    ArgumentCaptor<UserJpaEntity> userJpaCaptor;

    @Captor
    ArgumentCaptor<RoleJpaEntity> roleJpaCaptor;

    @Test
    void testRegisterNewUser() {
        // Given:
        UserDto userDto = UserDto.builder()
                .username("fbar")
                .password("password")
                .firstName("Foo")
                .lastName("Bar")
                .email("fbar@example.com")
                .roles(asList("ROLE_USER"))
                .build();
        userJpaCaptor = ArgumentCaptor.forClass(UserJpaEntity.class);
        RoleJpaEntity roleJpaEntity = new RoleJpaEntity();
        roleJpaEntity.setName("ROLE_USER");
        when(mockRoleRepo.findByName(eq("ROLE_USER"))).thenReturn(roleJpaEntity);

        // When:
        UserDto result = adapter.registerNewUser(userDto);

        // Then:
        assertThat("Returned UserDto;", result, notNullValue());
        verify(mockUserRepo).save(userJpaCaptor.capture());
        UserJpaEntity userJpaEntity = userJpaCaptor.getValue();
        assertThat("Username;", userJpaEntity.getUsername(), is("fbar"));
        assertThat("Password;", userJpaEntity.getPassword(), is("password"));
        assertThat("First name;", userJpaEntity.getFirstName(), is("Foo"));
        assertThat("Last name;", userJpaEntity.getLastName(), is("Bar"));
        assertThat("Email", userJpaEntity.getEmail(), is("fbar@example.com"));
        assertThat("Roles;", userJpaEntity.getRoles(), hasSize(1));
        assertThat("User role;", userJpaEntity.getRoles().iterator().next().getName(), is("ROLE_USER"));
    }

    @Test
    void testFindByUsername() {

    }
}
