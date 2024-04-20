package com.example.multiauthn.domain;

import java.util.List;

import com.example.multiauthn.domain.validation.PasswordMatches;
import com.example.multiauthn.domain.validation.ValidEmail;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@PasswordMatches
public class UserDto {

    @NotNull
    @Size(min = 1, message = "{Size.userDto.username}")
    private String username;

    @NotNull
    @Size(min = 1, message = "{Size.userDto.firstName}")
    private String firstName;

    @NotNull
    @Size(min = 1, message = "{Size.userDto.lastName}")
    private String lastName;

    private String password;

    @NotNull
    @Size(min = 1)
    private String matchingPassword;

    @ValidEmail
    @NotNull
    @Size(min = 1, message = "{Size.userDto.email}")
    private String email;

    private List<String> roles;
}
