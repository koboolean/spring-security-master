package io.security.springsecuritymaster.security.configs;

import io.security.springsecuritymaster.security.dsl.RestApiDsl;
import io.security.springsecuritymaster.security.entrypoint.RestAuthenticationEntryPoint;
import io.security.springsecuritymaster.security.filter.RestAuthenticationFilter;
import io.security.springsecuritymaster.security.handler.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationProvider authenticationProvider;
    private final AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource;
    private final FormAuthenticationSuccessHandler authenticationSuccessHandler;
    private final FormAuthenticationFailureHandler authenticationFailureHandler;

    private final AuthenticationProvider restAuthenticationProvider;
    private final RestAuthenticationSuccessHandler restAuthenticationSuccessHandler;
    private final RestAuthenticationFailureHandler restAuthenticationFailureHandler;

    /**
     * Server와 함께 사용하는 thymeleaf 방식을 사용
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                // 정적자원 permitAll
                .requestMatchers("/css/**", "/images/**", "/js/**", "/favicon.*", "/*/icon-*").permitAll()
                .requestMatchers("/", "/signup", "/login*").permitAll()
                .requestMatchers("/user").hasAuthority("ROLE_USER")
                .requestMatchers("/manager").hasAuthority("ROLE_MANAGER")
                .requestMatchers("/admin").hasAuthority("ROLE_ADMIN")
                .anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage("/login").permitAll()
                        .authenticationDetailsSource(authenticationDetailsSource)
                        .successHandler(authenticationSuccessHandler)
                        .failureHandler(authenticationFailureHandler))
                //.userDetailsService(userDetailsService);
                .authenticationProvider(authenticationProvider)
                .exceptionHandling(exception -> exception.accessDeniedHandler(new FormAccessDeniedHandler("/denied")));

        return http.build();
    }

    /**
     * Rest 방식의 인증 사용자 정의 보안
     */
    @Bean
    @Order(1)
    public SecurityFilterChain securityFilterChain1(HttpSecurity http, RestAuthenticationSuccessHandler restSuccessHandler, RestAuthenticationFailureHandler restFailureHandler) throws Exception {

        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.authenticationProvider(restAuthenticationProvider);
        AuthenticationManager authenticationManager = authenticationManagerBuilder.build();

        http.securityMatcher("/api/**")
                .authorizeHttpRequests(auth -> auth
                .requestMatchers("/css/**", "/images/**", "/js/**", "/favicon.*", "/*/icon-*").permitAll()
                        .requestMatchers("/api","/api/login").permitAll()
                        .requestMatchers("/api/user").hasAuthority("ROLE_USER")
                        .requestMatchers("/api/manager").hasAuthority("ROLE_MANAGER")
                        .requestMatchers("/api/admin").hasAuthority("ROLE_ADMIN")
                        .anyRequest().authenticated())
                //.csrf(AbstractHttpConfigurer::disable)
                // dsl 기능으로 인해 필요없음
                //.addFilterBefore(restAuthenticationFilter(http, authenticationManager), UsernamePasswordAuthenticationFilter.class)
                .authenticationManager(authenticationManager)
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(new RestAuthenticationEntryPoint())
                        .accessDeniedHandler(new RestAccessDeniedHandler())
                )
                .with(new RestApiDsl<>(), restDsl -> restDsl
                        .restSuccessHandler(restSuccessHandler)
                        .restFailureHandler(restFailureHandler)
                        //.loginPage("/api/login") // 필요없음
                        .loginProcessingUrl("/api/login") // RestAuthenticationFilter 생성자에 설정부분과 같으며 해당 부분이 우선순위가 높다.
                );

        return http.build();
    }

    /**
     * 필터 연결을 위한 method (dsl 설정으로 인해 필요없음)

    private RestAuthenticationFilter restAuthenticationFilter(HttpSecurity http, AuthenticationManager authenticationManager) {
        RestAuthenticationFilter restAuthenticationFilter = new RestAuthenticationFilter(http);
        restAuthenticationFilter.setAuthenticationManager(authenticationManager);
        restAuthenticationFilter.setAuthenticationSuccessHandler(restAuthenticationSuccessHandler);
        restAuthenticationFilter.setAuthenticationFailureHandler(restAuthenticationFailureHandler);
        return restAuthenticationFilter;
    }
     * */

}
