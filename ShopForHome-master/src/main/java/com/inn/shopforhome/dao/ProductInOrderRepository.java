package com.inn.shopforhome.dao;

import org.springframework.data.jpa.repository.JpaRepository;

import com.inn.shopforhome.model.ProductInOrder;


public interface ProductInOrderRepository extends JpaRepository<ProductInOrder, Long> {

}
