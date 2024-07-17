package io.security.springsecuritymaster.users.controller;

import io.security.springsecuritymaster.users.domain.dto.AccountDTO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class RestApiController {
    @GetMapping("/user")
    public AccountDTO restUser(@AuthenticationPrincipal AccountDTO accountDTO) {
        return accountDTO;
    }

    @GetMapping("/manager")
    public AccountDTO restManager(@AuthenticationPrincipal AccountDTO accountDTO) {
        return accountDTO;
    }

    @GetMapping("/admin")
    public AccountDTO restAdmin(@AuthenticationPrincipal AccountDTO accountDTO) {
        return accountDTO;
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication authentication = SecurityContextHolder.getContextHolderStrategy().getContext().getAuthentication();
        if(authentication != null) {
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }

        return "logout";
    }
}
