package com.inn.shopforhome.jwt;

import java.util.List;

public class JWTAuthenticationResponse {
	
	private String token;
	
	private List<String> roles;
	
	public JWTAuthenticationResponse(String token, List<String> roles){
		this.token=token;
		this.roles = roles;
	}

	public String getToken() {
		return token;
	}
	
	public List<String> getRoles() {
		return roles;
	}
}
