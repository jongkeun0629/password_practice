package com.example.password_practice.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.time.LocalDateTime;

@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    @NotBlank(message = "사용자명은 필수입니다.")
    @Size(min = 3, max = 20, message = "사용자명은 3-20자여야 합니다.")
    private String username;

    @Column(nullable = false)
    @NotBlank(message = "패스워드는 필수입니다")
    private String password; // 해시된 패스워드가 저장

    @Column(unique = true, nullable = false)
    @Email(message = "올바른 이메일 형식이어야 합니다.")
    private String email;

    @Column(nullable = false)
    private Boolean enabled = true;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "password_changed_at")
    private LocalDateTime passwordChangedAt;

    protected User(){}

    public User(String username, String password, String email){
        this.username = username;
        this.password = password;
        this.email = email;
        this.createdAt = LocalDateTime.now();
        this.passwordChangedAt = LocalDateTime.now();
    }

    // Getter
    public Long getId() { return id; }
    public String getUsername() { return username; }
    public String getPassword() { return password; }
    public String getEmail() { return email; }
    public Boolean getEnabled() { return enabled; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getPasswordChangedAt() { return passwordChangedAt; }

    // Setter
    public void setUsername(String username) { this.username = username; }

    // 패스워드 설정 시 변경 시간 업데이트
    public void setPassword(String password) {
        this.password = password;
        this.passwordChangedAt = LocalDateTime.now();
    }
    public void setEmail(String email) { this.email = email; }
    public void setEnabled(Boolean enabled) { this.enabled = enabled; }

    @Override
    public String toString() {
        return  "User{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", email='" + email + '\'' +
                ", enabled=" + enabled +
                ", createdAt=" + createdAt +
                '}';
    }
}
