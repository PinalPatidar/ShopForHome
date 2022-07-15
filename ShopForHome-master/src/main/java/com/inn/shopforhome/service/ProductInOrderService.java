package com.inn.shopforhome.service;

import com.inn.shopforhome.model.ProductInOrder;
import com.inn.shopforhome.model.User;

public interface ProductInOrderService {
    void update(String itemId, Integer quantity, User user);
    ProductInOrder findOne(String itemId, User user);
}
