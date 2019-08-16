package com.example.securityjwt.config;


import com.auth0.jwt.JWT;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req,
                                                HttpServletResponse res) throws AuthenticationException {
        try {
            ApplicationUser creds = new ObjectMapper()
                    .readValue(req.getInputStream(), ApplicationUser.class);

            System.out.println(creds.getUsername()+","+creds.getPassword());
            
            System.out.println("before");
            Authentication auth= authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            creds.getUsername(),
                            creds.getPassword(),
                            new ArrayList<>())
            );
           
            System.out.println("after");
            /*SimpleGrantedAuthority simpleGrantedAuthority=new SimpleGrantedAuthority(
					"ROLE_ADMIN"
					);
			
			List <GrantedAuthority>grantedAuthorityList=new ArrayList<GrantedAuthority>();
			grantedAuthorityList.add(simpleGrantedAuthority);
			Authentication auth1= new UsernamePasswordAuthenticationToken("user","password",grantedAuthorityList);
	        */
	        System.out.println("is"+auth.isAuthenticated());
            System.out.println(auth.getPrincipal());
              return auth;
        } catch (IOException e) {
        	System.out.println(e);
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest req,
                                            HttpServletResponse res,
                                            FilterChain chain,
                                            Authentication auth) throws IOException, ServletException {
    	String userNAme=auth.getName();
		System.out.println(userNAme);
    	
        String token = JWT.create()
        		.withSubject(userNAme+" userdetails")
        		.withClaim("demo", "demovalue")
                .withClaim("dob", new Date())
                .withClaim("role", "admin")
                .withClaim("email", "murali@mail.com")
                .withExpiresAt(new Date(System.currentTimeMillis() + SecurityConstants.EXPIRATION_TIME))
                .sign(HMAC512(SecurityConstants.SECRET.getBytes()));
        System.out.println("toke:"+token);
        PrintWriter out=res.getWriter();
        String accesJson =
        	    "{ \"accesstoken\" : \""+token+"\"}";
        out.println(accesJson);
        res.setContentType("application/json");
        //res.setStatus(204);
        res.addHeader(SecurityConstants.HEADER_STRING, SecurityConstants.TOKEN_PREFIX + token);
    }
}
