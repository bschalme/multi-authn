package com.example.multiauthn.application.port.out;

import com.example.multiauthn.domain.UserDto;

public interface UserPort {
    UserDto registerNewUser(UserDto user);
    UserDto findByUsername(String userName);
}
