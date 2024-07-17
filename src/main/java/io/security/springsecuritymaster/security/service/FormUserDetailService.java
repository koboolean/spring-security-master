package io.security.springsecuritymaster.security.service;

import io.security.springsecuritymaster.users.domain.dto.AccountContext;
import io.security.springsecuritymaster.users.domain.dto.AccountDTO;
import io.security.springsecuritymaster.users.domain.entity.Account;
import io.security.springsecuritymaster.users.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.ui.ModelMap;

import java.util.List;


@Service("userDetailsService")
@RequiredArgsConstructor
public class FormUserDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = userRepository.findByUsername(username);

        if (account == null) {
            throw new UsernameNotFoundException("No user found with username: " + username);
        }

        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(account.getRoles()));

        ModelMapper mapper = new ModelMapper();
        AccountDTO dto = mapper.map(account, AccountDTO.class);

        return new AccountContext(dto, authorities);
    }
}
