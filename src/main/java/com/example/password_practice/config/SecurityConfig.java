package com.example.password_practice.config;

import com.example.password_practice.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired
    private CustomUserDetailsService userDetailsService;

    /**
     * BCrypt 패스워드 인코더 설정
     * Cost Factor 12 사용 (2^12 = 4,096번 해싱)
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        // - 4~6: 테스트용 (빠르지만 보안 약함)
        // - 10~12: 운영환경 권장 (균형잡힌 보안과 성능)
        // - 13~15: 고보안 환경 (느리지만 매우 안전)

        int costFactor = 12;

        System.out.println("🔐 BCrypt 패스워드 인코더 설정");
        System.out.println("📊 Cost Factor: " + costFactor + " (2^" + costFactor + " = " +
                Math.pow(2, costFactor) + "번 해싱)");

        return new BCryptPasswordEncoder(costFactor);
    }

    /**
     * 보안 필터 체인 설정
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/register", "/h2-console/**", "/css/**", "/js/**", "/error").permitAll()
                        .requestMatchers("/password-test/**").permitAll()   // 테스트용
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form.loginPage("/login").permitAll()
                        .defaultSuccessUrl("/dashboard", true)
                        .failureUrl("/login?error=true")
                )
                .logout(logout -> logout
                        .logoutSuccessUrl("/login?logout=true")
                        .permitAll()
                )
                // H2 콘솔을 위한 설정
                .headers(headers -> headers.frameOptions(frame -> frame.disable()))
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers("/h2-console/**")
                        .ignoringRequestMatchers("/password-test/**")
                        .ignoringRequestMatchers("/register")
                )
                // 세션 관리 설정
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .enableSessionUrlRewriting(false)   // URL에 세션ID 포함 방지
                )
                .build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }
}
