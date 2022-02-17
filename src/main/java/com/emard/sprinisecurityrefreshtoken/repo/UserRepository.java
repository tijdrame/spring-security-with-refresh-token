package com.emard.sprinisecurityrefreshtoken.repo;

import com.emard.sprinisecurityrefreshtoken.domain.AppUser;

import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<AppUser, Long> {
    AppUser findByUsername(String username);
}
