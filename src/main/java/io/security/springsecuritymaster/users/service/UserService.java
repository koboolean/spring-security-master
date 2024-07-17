package io.security.springsecuritymaster.users.service;

import io.security.springsecuritymaster.users.domain.dto.AccountDTO;
import io.security.springsecuritymaster.users.domain.entity.Account;
import io.security.springsecuritymaster.users.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Transactional
    public void createUser(Account account){
        userRepository.save(account);
    }
}
