package com.example.securitydemo.entity;

import java.util.Collection;
import java.util.Set;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
import javax.persistence.Transient;
import javax.persistence.Id;
import javax.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Entity
@Table(name = "t_user")
@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class User implements UserDetails {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;
  @Size(min = 2, message = "Не меньше 5 знаков")
  private String username;
  @Size(min = 2, message = "Не меньше 5 знаков")
  private String password;
  @Transient
  private String passwordConfirm;
  @ManyToMany(fetch = FetchType.EAGER)
  private Set<Role> roles;

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return getRoles();
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }
}