package com.vaultapi.services;

import com.vaultapi.dto.UserRequestDto;
import com.vaultapi.dto.enums.Plans;
import com.vaultapi.dto.enums.Roles;
import com.vaultapi.entity.UserEntity;
import com.vaultapi.error.UserAlreadyExistsException;
import com.vaultapi.repo.UserRepo;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;

/**
 * The UserDetailsService AuthenticationManager is built from. It must not inject
 * AuthenticationManager itself - see AuthService for why. Login lives there.
 */
@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

    private final UserRepo userRepo;
    private final ModelMapper modelMapper;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepo.findByUsername(username).orElseThrow(
                () -> new UsernameNotFoundException("User not found with username: " + username)
        );
    }

    public UserEntity signUp(UserRequestDto userRequestDto) {
        // Duplicate check first: bcrypt is deliberately slow, don't spend it on a request we reject.
        if (userRepo.findByUsername(userRequestDto.getUsername()).isPresent()) {
            throw new UserAlreadyExistsException("Username already taken: " + userRequestDto.getUsername());
        }

        UserEntity userEntity = modelMapper.map(userRequestDto, UserEntity.class);
        // Encode from the request, not from the entity - the entity is only ever a destination here.
        userEntity.setPassword(passwordEncoder.encode(userRequestDto.getPassword()));
        // Roles and plan are server decisions. Signup always produces FREE + ROLE_USER.
        userEntity.setRoles(Set.of(Roles.USER));
        userEntity.setPlans(Plans.FREE);

        return userRepo.save(userEntity);
    }
}
