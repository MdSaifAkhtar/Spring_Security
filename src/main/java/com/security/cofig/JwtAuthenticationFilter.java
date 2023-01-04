package com.security.cofig;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.security.helper.JwtUtil;
import com.security.services.CustomUserDetailsService;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
	@Autowired
	private CustomUserDetailsService CcustomUserDetailsService;
	@Autowired
	private JwtUtil jwtutil;
	
	
@Override
protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException
{
String tokenhead = request.getHeader("Authorization");
String username= null;
String jwtToken=null;
if(tokenhead!=null && tokenhead.startsWith("Bearer"))
{
	jwtToken = tokenhead.substring(7);
}

try {
	username = this.jwtutil.extractUsername(jwtToken);
}
catch(Exception e)
{
	e.printStackTrace();
}

UserDetails userdetails = this.CcustomUserDetailsService.loadUserByUsername(username);
if(username!=null && SecurityContextHolder.getContext().getAuthentication()==null)
{
	
UsernamePasswordAuthenticationToken usernamepassword = new  UsernamePasswordAuthenticationToken(userdetails, null,userdetails.getAuthorities());
usernamepassword.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
SecurityContextHolder.getContext().setAuthentication(usernamepassword);
}
else {
	System.out.println("Token is not validate");
}




filterChain.doFilter(request, response);
}
}
