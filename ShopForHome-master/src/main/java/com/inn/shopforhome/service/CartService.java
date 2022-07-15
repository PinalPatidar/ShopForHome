package com.inn.shopforhome.service;

import java.util.Collection;

import com.inn.shopforhome.model.Cart;
import com.inn.shopforhome.model.ProductInOrder;
import com.inn.shopforhome.model.User;


public interface CartService {
    Cart getCart(User user);

    void mergeLocalCart(Collection<ProductInOrder> productInOrders, User user);

    void delete(String itemId, User user);

    void checkout(User user);
}
