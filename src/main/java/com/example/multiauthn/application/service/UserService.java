package com.example.multiauthn.application.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.multiauthn.application.port.in.RegistrationUseCase;
import com.example.multiauthn.application.port.out.UserPort;
import com.example.multiauthn.domain.UserDto;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserService implements RegistrationUseCase {

    private final UserPort userPort;

    private final PasswordEncoder passwordEncoder;

    @Override
    public void registerNewUserAccount(UserDto accountDto) {
        accountDto.setPassword(passwordEncoder.encode(accountDto.getPassword()));
        userPort.registerNewUser(accountDto);
    }
    
}
