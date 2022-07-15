package com.inn.shopforhome.dao;

import org.springframework.data.jpa.repository.JpaRepository;

import com.inn.shopforhome.model.Discount;

public interface DiscountRepository extends JpaRepository<Discount, String> {

}
