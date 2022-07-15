package com.inn.shopforhome.dao;


import org.springframework.data.jpa.repository.JpaRepository;

import com.inn.shopforhome.model.User;

import java.util.Collection;


public interface UserRepository extends JpaRepository<User, String> {
    User findByEmail(String email);
    Collection<User> findAllByRole(String role);

}
