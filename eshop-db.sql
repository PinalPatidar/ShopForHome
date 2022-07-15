-- MySQL dump 10.13  Distrib 8.0.29, for Win64 (x86_64)
--
-- Host: localhost    Database: eshop
-- ------------------------------------------------------
-- Server version	8.0.29

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `cart`
--

DROP TABLE IF EXISTS `cart`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `cart` (
  `user_id` bigint NOT NULL,
  PRIMARY KEY (`user_id`),
  CONSTRAINT `FKg5uhi8vpsuy0lgloxk2h4w5o6` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `cart`
--

LOCK TABLES `cart` WRITE;
/*!40000 ALTER TABLE `cart` DISABLE KEYS */;
INSERT INTO `cart` VALUES (1),(3);
/*!40000 ALTER TABLE `cart` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `discount`
--

DROP TABLE IF EXISTS `discount`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `discount` (
  `id` varchar(255) NOT NULL,
  `status` bigint DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `discount`
--

LOCK TABLES `discount` WRITE;
/*!40000 ALTER TABLE `discount` DISABLE KEYS */;
INSERT INTO `discount` VALUES ('001',0);
/*!40000 ALTER TABLE `discount` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `hibernate_sequence`
--

DROP TABLE IF EXISTS `hibernate_sequence`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `hibernate_sequence` (
  `next_val` bigint DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `hibernate_sequence`
--

LOCK TABLES `hibernate_sequence` WRITE;
/*!40000 ALTER TABLE `hibernate_sequence` DISABLE KEYS */;
INSERT INTO `hibernate_sequence` VALUES (13),(13),(13),(13),(13),(13),(13),(13),(13),(13);
/*!40000 ALTER TABLE `hibernate_sequence` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `order_main`
--

DROP TABLE IF EXISTS `order_main`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `order_main` (
  `order_id` bigint NOT NULL,
  `buyer_address` varchar(255) DEFAULT NULL,
  `buyer_email` varchar(255) DEFAULT NULL,
  `buyer_name` varchar(255) DEFAULT NULL,
  `buyer_phone` varchar(255) DEFAULT NULL,
  `create_time` datetime(6) DEFAULT NULL,
  `order_amount` decimal(19,2) NOT NULL,
  `order_status` int NOT NULL DEFAULT '0',
  `update_time` datetime(6) DEFAULT NULL,
  PRIMARY KEY (`order_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `order_main`
--

LOCK TABLES `order_main` WRITE;
/*!40000 ALTER TABLE `order_main` DISABLE KEYS */;
INSERT INTO `order_main` VALUES (10,'14-D Sarvanand  nagar,bholaram ustad marg indore, Utsav girls  hostel','pinal@eshop.com','pinal','6260126222','2022-07-10 16:48:49.111596',82.00,2,'2022-07-13 11:47:27.917562');
/*!40000 ALTER TABLE `order_main` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `product_category`
--

DROP TABLE IF EXISTS `product_category`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `product_category` (
  `category_id` int NOT NULL,
  `category_name` varchar(255) DEFAULT NULL,
  `category_type` int DEFAULT NULL,
  `create_time` datetime(6) DEFAULT NULL,
  `update_time` datetime(6) DEFAULT NULL,
  PRIMARY KEY (`category_id`),
  UNIQUE KEY `UK_6kq6iveuim6wd90cxo5bksumw` (`category_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `product_category`
--

LOCK TABLES `product_category` WRITE;
/*!40000 ALTER TABLE `product_category` DISABLE KEYS */;
INSERT INTO `product_category` VALUES (2147483641,'chairs',0,'2022-06-23 23:03:26.000000','2022-06-23 23:03:26.000000'),(2147483642,'mirrors',1,'2022-06-23 23:03:26.000000','2022-06-23 23:03:26.000000'),(2147483643,'sofa',2,'2022-06-23 23:03:26.000000','2022-06-23 23:03:26.000000'),(2147483644,'clocks',3,'2022-06-23 23:03:26.000000','2022-06-23 23:03:26.000000');
/*!40000 ALTER TABLE `product_category` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `product_in_order`
--

DROP TABLE IF EXISTS `product_in_order`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `product_in_order` (
  `id` bigint NOT NULL,
  `category_type` int NOT NULL,
  `count` int DEFAULT NULL,
  `product_description` varchar(255) NOT NULL,
  `product_icon` varchar(255) DEFAULT NULL,
  `product_id` varchar(255) DEFAULT NULL,
  `product_name` varchar(255) DEFAULT NULL,
  `product_price` decimal(19,2) NOT NULL,
  `product_stock` int DEFAULT NULL,
  `cart_user_id` bigint DEFAULT NULL,
  `order_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `FKhnivo3fl2qtco3ulm4mq0mbr5` (`cart_user_id`),
  KEY `FKt0sfj3ffasrift1c4lv3ra85e` (`order_id`),
  CONSTRAINT `FKhnivo3fl2qtco3ulm4mq0mbr5` FOREIGN KEY (`cart_user_id`) REFERENCES `cart` (`user_id`),
  CONSTRAINT `FKt0sfj3ffasrift1c4lv3ra85e` FOREIGN KEY (`order_id`) REFERENCES `order_main` (`order_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `product_in_order`
--

LOCK TABLES `product_in_order` WRITE;
/*!40000 ALTER TABLE `product_in_order` DISABLE KEYS */;
INSERT INTO `product_in_order` VALUES (9,0,1,'A book for self awareness and improvement','https://m.media-amazon.com/images/I/81gTwYAhU7L._AC_UL480_FMwebp_QL65_.jpg','AF003','The Power of your Subconscious Mind',82.00,20,NULL,10),(12,0,2,'How to Find Balance and Purpose in Your Life | Inspirational Zen book on motivation, self-development & healthy living','https://m.media-amazon.com/images/I/81N7FmJhbhL._AC_UY327_FMwebp_QL65_.jpg','AF001','Life\'s Amazing Secrets ',162.00,9,NULL,NULL);
/*!40000 ALTER TABLE `product_in_order` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `product_info`
--

DROP TABLE IF EXISTS `product_info`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `product_info` (
  `product_id` varchar(255) NOT NULL,
  `category_type` int DEFAULT '0',
  `create_time` datetime(6) DEFAULT NULL,
  `product_description` varchar(255) DEFAULT NULL,
  `product_icon` varchar(255) DEFAULT NULL,
  `product_name` varchar(255) NOT NULL,
  `product_price` decimal(19,2) NOT NULL,
  `product_status` int DEFAULT '0',
  `product_stock` int NOT NULL,
  `update_time` datetime(6) DEFAULT NULL,
  PRIMARY KEY (`product_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `product_info`
--

LOCK TABLES `product_info` WRITE;
/*!40000 ALTER TABLE `product_info` DISABLE KEYS */;
INSERT INTO `product_info` VALUES ('AF001',0,'2022-06-23 23:03:26.000000','Futura Plastic Chairs (Set of 4, Brown)','https://m.media-amazon.com/images/I/61WJxpNzOVL._SX466_.jpg','Futura Plastic Chairs',1200.00,0,9,'2022-07-14 12:37:39.787000'),('AF002',0,'2022-06-23 23:03:26.000000','Ikea Adde Chair (Steel , White)','https://m.media-amazon.com/images/I/2170L0L599S.jpg','Ikea Adde Chair',2599.00,0,75,'2022-07-14 14:06:27.881000'),('AF003',0,'2022-06-23 23:03:26.000000','Modern Furniture Plastic Chairs with Cushion Grey Colo','https://m.media-amazon.com/images/I/81iSHWHI1LL._SX679_.jpg','Modern Furniture Plastic Chair',2999.00,0,20,'2022-07-14 12:39:40.371000'),('B0001',0,'2018-03-10 06:44:25.000000','Honey Touch Folding Wrought Iron Chair with Cushion & Adjustable Writing Pad Multipurpose Ergonomic Design (with Tablet)','https://m.media-amazon.com/images/I/91MojJFaZTL._SX679_.jpg','Adjustable Writing Pad Multipurpose Ergonomic chair',3299.00,0,93,'2022-07-14 14:07:45.882000'),('B0002',0,'2018-03-10 10:35:43.000000','Rose Designer Chairs Modern Ergonomic Office Chair (Leather , Brown)','https://m.media-amazon.com/images/I/71uzYX3DZqL._SX679_.jpg','premium Office Executive Chair',5999.00,0,195,'2022-07-14 14:09:13.115000'),('B00021',1,'2022-07-13 11:45:41.494000','Hexagon 20 Silver Decorative Mirror Stickers For Wall Large Size, 3d Acrylic Stickers.  (52 cm X 45 cm, Silver)\n','https://m.media-amazon.com/images/I/71Ty2jMmamL._SX679_.jpg','Hexagon 20 Silver Decorative Mirror Stickers',350.00,0,25,'2022-07-14 14:12:57.499000'),('B00022',1,'2022-07-13 11:45:41.505000','Round Wall Mirror for Bathroom Wash Basin Living Room Bedroom Drawing Room - Silver, 12 Inches','https://m.media-amazon.com/images/I/51vs9srPIAL._SX679_.jpg','Makeup Vanity Round Wall Mirror',499.00,0,30,'2022-07-14 14:13:46.743000'),('B0003',1,'2018-03-10 10:37:39.000000','Long Fiber Wood Rectangular Wall Hanging Wall for Bedroom ','https://m.media-amazon.com/images/I/51xEix3R5vL._SL1024_.jpg','Long Fiber Wood Rectangular Wall ',1994.00,0,200,'2022-07-14 12:54:35.614000'),('B0004',1,'2018-03-10 10:39:29.000000','Art Street Decorative Wall Mirror for Bathroom/Vanity .Black Basics Synthetic Wood (Black, 15 X 21 Inches)','https://m.media-amazon.com/images/I/71p48nS1rML._SL1300_.jpg ','Art Street Wall Mirror',30.00,0,799,'2022-07-14 14:14:55.210000'),('B0005',2,'2018-03-10 10:40:35.000000','WOODTREND Solid Teak Wood Sofa Cums Bed For Home Living Room \n','https://m.media-amazon.com/images/I/61hDhiyIQBL._SL1000_.jpg','Solid Teak Wood Sofa Cums Bed',1599.00,0,199,'2022-07-14 14:16:09.143000'),('C0001',2,'2018-03-10 12:09:41.000000','Solimo Venosa Fabric 6 Seater RHS L Shape Sofa','https://m.media-amazon.com/images/I/91tMzaIomiL._SX466_.jpg','Solimo Venosa Fabric 6 Seater RHS L Shape Sofa (Blue)',38999.00,0,109,'2022-07-14 14:17:02.083000'),('C0002',2,'2018-03-10 12:11:51.000000','Bed/Convertible Couch Bed/Chair Bed with Pillow 5 Position/Sofa/Bed/Folding Bed (Blue) (2 Seater)','https://m.media-amazon.com/images/I/61omTOQrLTL._SL1000_.jpg','Furnline 2 Seater Folding Sofa',18999.00,0,108,'2022-07-14 14:17:48.951000'),('C0003',2,'2018-03-10 12:12:46.000000','Furny Fronssy 5 Seater 3+2 Fabric Sofa Set (Dark-Grey)','https://m.media-amazon.com/images/I/61utZga-DDL._SL1100_.jpg','Furny Fronssy 5 Seater',33864.00,0,222,'2022-07-14 14:18:35.312000'),('D0001',3,'2018-03-10 06:51:03.000000','Wall Clock for Home Raawan 12\" Silent Quartz Non Ticking Classic Battery Operated Easy to Read wall clock','https://m.media-amazon.com/images/I/61RkRYjfBIL._SL1500_.jpg ','Non-Ticking Classic Clock',1599.00,0,100,'2022-07-14 14:21:25.884000'),('D0002',0,'2018-03-10 12:08:17.000000','Lenovo Smart Clock Essential with Alexa Built-in (Misty Blue)','https://m.media-amazon.com/images/I/81hYFRo+oNL._SL1500_.jpg','Lenovo Smart Clock Essential with Alexa Built-in',2000.00,0,200,'2022-07-14 14:21:57.147000'),('F0001',3,'2018-03-10 12:15:05.000000','Solimo Wood Abstract 12\" Silent Movement Wall Clock (Sheer Black Frame)','https://m.media-amazon.com/images/I/81iUk1N-1lL._SL1500_.jpg','Solimo Wood Abstract 12\" Silent Movement Wall Clock',1499.00,0,57,'2022-07-14 14:23:21.085000'),('F0002',3,'2018-03-10 12:16:44.000000','Estron Analog Latest Stylish New Models Wall Clock with Photo Frames for Home Living Room Hall Bedroom (Size Height 30 cm X Width 29 cm)','https://m.media-amazon.com/images/I/71vMgcGvoJL._SL1500_.jpg ','Latest Stylish wall clock wood',2399.00,0,22,'2022-07-14 14:24:36.073000'),('IF001',3,'2022-06-23 23:03:26.000000','SAYKHUS Acrylic Digital LED Number Clock Table/Wall Hanging Alarm Clock, Multicolour','https://m.media-amazon.com/images/I/31Hp87eAHXL.jpg','Digital LED Number Clock Table',999.00,0,22,'2022-07-14 14:26:51.983000'),('IF002',3,'2022-06-23 23:03:26.000000','vintage wall clock for home','https://m.media-amazon.com/images/I/61WSWBOZ-JL._AC_SX768_SY576_.jpg','vintage wall clock for home ',3499.00,0,60,'2022-07-14 13:05:45.149000'),('IF003',3,'2022-06-23 23:03:26.000000','Craftter 24 inch Gold Color Sober Metal Wall Clock','https://m.media-amazon.com/images/I/810I00hFIRS._SX679_.jpg','Craftter 24 inch Gold Color Sober Metal Wall Clock',2269.00,0,40,'2022-07-14 13:06:34.752000'),('PA001',2,'2022-06-23 23:03:26.000000','Sleepyhead Yolo - 3 Seater Sofa (Fabric, Sesame Grey)','https://m.media-amazon.com/images/I/61Ty5s3bmVL._SL1000_.jpg','Sleepyhead Yolo - 3 Seater Sofa',22229.00,0,45,'2022-07-14 14:28:17.042000'),('PA002',1,'2022-06-23 23:03:26.000000','Wall Mounted Hanging Mirror Sculpture Metal Golden Rose Design Modern Art Mirror for Home Decor','https://m.media-amazon.com/images/I/91fMhIhHQbL._SL1500_.jpg','Decorative Mirror Wall Mounted Hanging Mirror',2089.00,0,53,'2022-07-14 14:29:03.596000');
/*!40000 ALTER TABLE `product_info` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` bigint NOT NULL,
  `active` bit(1) NOT NULL,
  `address` varchar(255) DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  `password` varchar(255) DEFAULT NULL,
  `phone` varchar(255) DEFAULT NULL,
  `role` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `UK_sx468g52bpetvlad2j9y0lptc` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (1,_binary '','14-D Shivay Girls Hostel, Sarvanand Nagar','pinalpatida67@gmail.com','Pinal Patidar','$2a$10$kaVr.t20QqzQnHx8pPBnzuC0LP4hf295mEXSNVDrCz4xgHZrBMG0q','6260126222','ROLE_CUSTOMER'),(3,_binary '','14-D Sarvanand  nagar,bholaram ustad marg indore, Utsav girls  hostel','pinal@eshop.com','pinal','$2a$10$UOoeH0EBUBv0JSKhw22PaODtrEz5Rd7sACQSZImPBZYepuIlv.XKq','6260126222','ROLE_CUSTOMER'),(2147483645,_binary '','360, Talawadi Road, Kukshi','admin@eshop.com','Admin','$2a$10$9zRl9DmvHilM0EazPhtJr.VRiQ4j/j9E28OEBcdoDjJpel7MNtbVy','6260126222','ROLE_MANAGER');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `wishlist`
--

DROP TABLE IF EXISTS `wishlist`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `wishlist` (
  `id` bigint NOT NULL,
  `created_date` datetime(6) DEFAULT NULL,
  `product_id` varchar(255) DEFAULT NULL,
  `user_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  KEY `FKklfv8svemdde0od1rs6mgstb` (`product_id`),
  KEY `FKtrd6335blsefl2gxpb8lr0gr7` (`user_id`),
  CONSTRAINT `FKklfv8svemdde0od1rs6mgstb` FOREIGN KEY (`product_id`) REFERENCES `product_info` (`product_id`),
  CONSTRAINT `FKtrd6335blsefl2gxpb8lr0gr7` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `wishlist`
--

LOCK TABLES `wishlist` WRITE;
/*!40000 ALTER TABLE `wishlist` DISABLE KEYS */;
INSERT INTO `wishlist` VALUES (2,'2022-07-09 18:40:00.696000','AF001',1),(8,'2022-07-10 14:03:40.323000','B0002',3),(11,'2022-07-10 21:28:16.026000','AF001',3);
/*!40000 ALTER TABLE `wishlist` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2022-07-14 14:31:08
