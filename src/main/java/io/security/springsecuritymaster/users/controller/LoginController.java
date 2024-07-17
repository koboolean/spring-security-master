package io.security.springsecuritymaster.users.controller;

import io.security.springsecuritymaster.users.domain.dto.AccountDTO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LoginController {

    @GetMapping("/login")
    public String login(@RequestParam(value = "error", required = false) String error,
                        @RequestParam(value = "exception", required = false) String exception, Model model){
        model.addAttribute("error",error);
        model.addAttribute("exception",exception);
        return "login/login";
    }

    /**
     * Rest 방식의 Login 접근
     * @return
     */
    @GetMapping("/api/login")
    public String restLogin() {
        return "rest/login";
    }

    @GetMapping("/signup")
    public String signup() {
        return "login/signup";
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication authentication = SecurityContextHolder.getContextHolderStrategy().getContext().getAuthentication();
        if(authentication != null){
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }

        return "redirect:/login";
    }


    @GetMapping("/denied")
    public String denied(@RequestParam(value = "exception", required = false) String exception
                        , @AuthenticationPrincipal AccountDTO accountDTO, Model model) {
        model.addAttribute("username", accountDTO.getUsername());
        model.addAttribute("exception", exception);

        return "login/denied";
    }
}
