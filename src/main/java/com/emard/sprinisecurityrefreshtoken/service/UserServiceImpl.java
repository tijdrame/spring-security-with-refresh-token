package com.emard.sprinisecurityrefreshtoken.service;

import java.util.List;

import com.emard.sprinisecurityrefreshtoken.domain.Role;
import com.emard.sprinisecurityrefreshtoken.domain.AppUser;
import com.emard.sprinisecurityrefreshtoken.repo.RoleRepository;
import com.emard.sprinisecurityrefreshtoken.repo.UserRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@AllArgsConstructor
@Transactional
public class UserServiceImpl implements UserService {

    private final UserRepository userRepo;
    private final RoleRepository roleRepo;

    @Override
    public AppUser saveUser(AppUser user) {
        log.info("saving new user [{}]", user);
        return userRepo.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("saving new role [{}]", role);
        return roleRepo.save(role);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        log.info("addRoleToUser username [{}] role [{}]", username, roleName);
        AppUser user = userRepo.findByUsername(username);     
        Role role = roleRepo.findByName(roleName);   
        user.getRoles().add(role);
    }

    @Override
    public AppUser getUser(String username) {
        log.info("getUser  username [{}]", username);
        return userRepo.findByUsername(username);
    }

    @Override
    public List<AppUser> getUsers() {
        log.info("getUsers ");
        return userRepo.findAll();
    }
    
}
