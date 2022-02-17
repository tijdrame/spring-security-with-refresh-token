package com.emard.sprinisecurityrefreshtoken.service;

import java.util.List;

import com.emard.sprinisecurityrefreshtoken.domain.Role;
import com.emard.sprinisecurityrefreshtoken.domain.AppUser;

public interface UserService {
    
    AppUser saveUser(AppUser user);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    AppUser getUser(String username);
    List<AppUser> getUsers();
}
