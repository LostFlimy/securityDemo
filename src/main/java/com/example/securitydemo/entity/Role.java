package com.example.securitydemo.entity;

import java.util.Set;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
import javax.persistence.Transient;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;

@Entity
@Table(name = "t_role")
@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class Role implements GrantedAuthority {
  @Id
  private Long id;
  private String name;
  @Transient
  @ManyToMany(mappedBy = "roles")
  private Set<User> users;

  @Override
  public String getAuthority() {
    return getName();
  }
}
