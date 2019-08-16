package com.example.securityjwt.config;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

	
	@RequestMapping(value="/login",method = RequestMethod.POST)
	public String doLogin(){
		System.out.println("hi");
		
		return "hi";
	}
}
