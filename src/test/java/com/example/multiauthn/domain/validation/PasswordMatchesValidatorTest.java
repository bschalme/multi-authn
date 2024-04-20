package com.example.multiauthn.domain.validation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;

import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.example.multiauthn.domain.UserDto;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;

class PasswordMatchesValidatorTest {
    private Validator validator;

    @BeforeEach
    public void setUp() {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @Test
    void passwordsMatch() {
        // Given:
        UserDto user = makeValidUserDto();

        // When:
        Set<ConstraintViolation<UserDto>> violations = validator.validate(user);

        // Then:
        assertThat(violations, hasSize(0));
    }

    @Test
    void passwordsMismatch() {
        // Given:
        UserDto user = makeValidUserDto();
        user.setMatchingPassword("Qwerty");

        // When:
        Set<ConstraintViolation<UserDto>> violations = validator.validate(user);

        // Then:
        assertThat(violations, hasSize(1));
    }

    private UserDto makeValidUserDto() {
        return UserDto.builder()
                .firstName("Jennifer")
                .lastName("Red")
                .username("jred")
                .password("qwerty")
                .matchingPassword("qwerty")
                .email("user@example.com")
                .build();
    }
}
