package io.security.springsecuritymaster.users.controller;

import io.security.springsecuritymaster.users.domain.dto.AccountDTO;
import io.security.springsecuritymaster.users.domain.entity.Account;
import io.security.springsecuritymaster.users.service.UserService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class UserController {

    private final PasswordEncoder passwordEncoder;

    private final UserService userService;

    /**
     * 회원가입
     * @param dto
     * @return
     */
    @PostMapping("/signup")
    public String signup(AccountDTO dto) {
        ModelMapper mapper = new ModelMapper();

        Account account = mapper.map(dto, Account.class);

        account.setPassword(passwordEncoder.encode(dto.getPassword()));

        userService.createUser(account);

        return "redirect:/";

    }
}
