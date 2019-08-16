package com.example.securityjwt.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/users")
public class UserController {

     private BCryptPasswordEncoder bCryptPasswordEncoder;

    public UserController(BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @PostMapping("/sign-up")
    public void signUp(@RequestBody ApplicationUser user) {
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
    }
    
    @GetMapping("/hello")
    public String sayHello(){
    	return "hello";
    }
    
    
    @GetMapping("/employees")
    public List<Employee> sayemployees(){
    	Employee e1=new Employee();
    	e1.setId(1001);
    	e1.setName("muruga");
    	e1.setSalary(4564.45f);
    	e1.setAge(100);
    	List<Employee> employees=new ArrayList<Employee>();
    	employees.add(e1);
    	return employees;
    }
    
    
    
}

