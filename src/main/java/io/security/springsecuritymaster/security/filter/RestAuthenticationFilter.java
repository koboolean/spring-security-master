package io.security.springsecuritymaster.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.springsecuritymaster.security.token.RestAuthenticationToken;
import io.security.springsecuritymaster.users.domain.dto.AccountDTO;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import io.security.springsecuritymaster.util.WebUtil;
import org.springframework.util.StringUtils;

import java.io.IOException;

public class RestAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public RestAuthenticationFilter() {
        super(new AntPathRequestMatcher("/api/login", "POST"));
        // dsl 사용으로 인한 해당 부분 불필요
        //setSecurityContextRepository(getSecurityContextRepository(http));
    }

    public SecurityContextRepository getSecurityContextRepository(HttpSecurity http) {
        SecurityContextRepository securityContextRepository = http.getSharedObject(SecurityContextRepository.class);
        if(securityContextRepository == null) {
            securityContextRepository = new DelegatingSecurityContextRepository(
                    new RequestAttributeSecurityContextRepository(), new HttpSessionSecurityContextRepository()
            );

        }
        return securityContextRepository;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        // 비동기 통신 유무 확인
        if(!HttpMethod.POST.name().equals(request.getMethod()) || !WebUtil.isAjax(request)){
            throw new IllegalArgumentException("Unsupported request method: " + request.getMethod());
        }

        AccountDTO accountDTO = objectMapper.readValue(request.getReader(), AccountDTO.class);
        if(!StringUtils.hasText(accountDTO.getUsername()) || !StringUtils.hasText(accountDTO.getPassword())){
            throw new AuthenticationServiceException("Username or password is incorrect");
        }

        RestAuthenticationToken authenticationToken = new RestAuthenticationToken(accountDTO.getUsername(), accountDTO.getPassword());

        return getAuthenticationManager().authenticate(authenticationToken);
    }
}
