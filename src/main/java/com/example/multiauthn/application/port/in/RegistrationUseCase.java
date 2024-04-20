package com.example.multiauthn.application.port.in;

import com.example.multiauthn.domain.UserDto;

public interface RegistrationUseCase {
    void registerNewUserAccount(UserDto accountDto);
}
