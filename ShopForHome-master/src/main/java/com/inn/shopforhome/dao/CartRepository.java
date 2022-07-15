package com.inn.shopforhome.dao;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.inn.shopforhome.model.Cart;


public interface CartRepository extends JpaRepository<Cart, Integer> {
}
