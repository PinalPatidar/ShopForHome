package com.rakuten.letsmeet.letsmeetbackend.jwt;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import javax.persistence.Column;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.rakuten.letsmeet.letsmeetbackend.model.Role;
import com.rakuten.letsmeet.letsmeetbackend.model.Users;

public class MyUserDetails implements UserDetails {

	private final Logger logger = LoggerFactory.getLogger(this.getClass());

	private Integer id;

	private String name;

	private String userName;

	private String password;

	private Boolean isEnable = false;

	private Collection<GrantedAuthority> authorities;

	public MyUserDetails(Users user) {
//			this.id = user.getId();
//			this.name = user.getName();
		this.userName = user.getUserName();
		this.password = user.getPassword();
		this.isEnable = user.getIsEnabled();
		List<Role> roles = user.getRoles();
		
		this.authorities = roles.stream().map(Role::getRoleName)
				.map(SimpleGrantedAuthority::new)
		        .collect(Collectors.toList());
		
		logger.info("MyUserDetails in constructor {} ", this);
	}

	public String getName() {
		return name;
	}

	public Integer getId() {
		return id;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public String getUsername() {
		return userName;
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
		return isEnable;
	}

	@Override
	public String toString() {
		return "MyUserDetails [id=" + id + ", name=" + name + ", userName=" + userName + ", password=" + password
				+ ", isEnable=" + isEnable + ", authorities=" + authorities + "]";
	}

}
