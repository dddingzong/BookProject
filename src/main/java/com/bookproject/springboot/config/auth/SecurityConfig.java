package com.bookproject.springboot.config.auth;

import com.bookproject.springboot.domain.user.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@RequiredArgsConstructor
@EnableWebSecurity //Spring Security 설정 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomOAuth2UserService customOAuth2UserService;

    @Override
    protected void configure(HttpSecurity http) throws Exception{
        http
                .csrf().disable()
                .headers().frameOptions().disable() //h2-console 화면을 사용하기 위해 해당 옵션 disable
                .and()
                    .authorizeRequests() // URL별 권환 관리 옵션
                    .antMatchers("/","/css/**","/images/**","/js/**","/h2-console/**", "/profile").permitAll()
                    .antMatchers("/api/v1/**").hasRole(Role.USER.name()) // "/api/v1/**" 는 USER 권한만 사용가능
                    .anyRequest().authenticated() // 나머지는 인증된 사용자 즉 로그인한 사용자들만 허용
                .and()
                    .logout()
                        .logoutSuccessUrl("/")
                .and()
                    .oauth2Login()
                        .userInfoEndpoint() //로그인 성공 이후 사용자 정보를 가져온다
                            .userService(customOAuth2UserService); // 로그인 성공 시 후속 조치를 진행할 UserService
    }

}
