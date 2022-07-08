package com.rakuten.letsmeet.letsmeetbackend.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

//import com.inn.deep.student.facultymodulejpa.user.service.MyUserDetailsService;
//import com.inn.deep.student.facultymodulejpa.utils.JWTUtils;
import com.rakuten.letsmeet.letsmeetbackend.model.Users;
import com.rakuten.letsmeet.letsmeetbackend.service.MyUserDetailsService;
import com.rakuten.letsmeet.letsmeetbackend.service.UserService;

import io.jsonwebtoken.ExpiredJwtException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
		
	private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
	
	@Autowired
	private UserService usersService;
	
	@Autowired
	private MyUserDetailsService myUserDetailsService;
	
	@Autowired
	private JWTUtils jWTUtils;
	
	@Value("${jwt.autorization.key}")
	private String authorization;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
			final String authenticationToken = request.getHeader(authorization);
			logger.error("Inside do filter {} ,{}", authorization, authenticationToken);
			String username=null;
			String token = null;
			if(authenticationToken!=null && authenticationToken.startsWith("Bearer ")) {
				token = authenticationToken.substring(7);
				try {
	                username = jWTUtils.getUsernameFromToken(token);
	            } catch (IllegalArgumentException e) {
	                logger.error("JWT_TOKEN_UNABLE_TO_GET_USERNAME", e);
	            } catch (ExpiredJwtException e) {
	                logger.warn("JWT_TOKEN_EXPIRED", e);
	            }
			}else {
				logger.debug("JWT_TOKEN_DOES_NOT_START_WITH_BEARER_STRING");
			}
			logger.debug("JWT_TOKEN_USERNAME_VALUE '{}'", username);
			if(username!=null && SecurityContextHolder.getContext().getAuthentication()==null) {
				UserDetails userDetails = myUserDetailsService.loadUserByUsername(username);
				if(Boolean.TRUE.equals(jWTUtils.validateToken(token, userDetails))) {
//					UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
					UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = jWTUtils.getAuthentication(token, userDetails);
					usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
					SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
				}
			}
			HttpServletResponse httpresponse = (HttpServletResponse) response;
			HttpServletRequest httprequest = (HttpServletRequest) request;
//			httpresponse.setHeader("Access-Control-Allow-Origin", "*");
//			httpresponse.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE");
//			httpresponse.setHeader("Access-Control-Max-Age", "3600");
//			httpresponse.setHeader("Access-Control-Allow-Headers", "x-requested-with, authorization");
//			
			httpresponse.setHeader("Access-Control-Allow-Origin", "*");
			httpresponse.setHeader("Access-Control-Allow-Headers", "X-API-KEY, Origin, X-Requested-With, Content-Type, Accept, Access-Control-Request-Method, Authorization");
			httpresponse.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE, PATCH");

	        if ("OPTIONS".equalsIgnoreCase(httprequest.getMethod())) {
	        	httpresponse.setStatus(HttpServletResponse.SC_OK);
	        } else {
	            chain.doFilter(request, response);
	        }
//	        chain.doFilter(request, response);
		
	}

}
