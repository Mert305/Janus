-- Chronova S.A. Production Database Dump
-- Host: db-prod-01.chronova.internal  Database: chronova_prod
-- Date: 2024-10-15 03:00:01

CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `email` varchar(150) NOT NULL,
  `password` varchar(255) NOT NULL,
  `role` enum('admin','staff','customer') DEFAULT 'customer',
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB;

INSERT INTO `users` VALUES
(1,'Heinrich Voss','h.voss@chronova.ch','$2y$12$xK9mP2nR4qL8sT1vW6uJ3hA0cB5eD7fG','admin','2024-01-10 09:00:00'),
(2,'Marie Dubois','m.dubois@chronova.ch','$2y$12$aQ7wE3rT5yU8iO9pL2kJ6hN1mB4vC0xZ','staff','2024-02-14 10:30:00'),
(3,'sysadmin','sysadmin@chronova.ch','$2y$12$Chr0nova2024AdminHash','admin','2024-01-01 00:00:00');

CREATE TABLE `products` (
  `id` int NOT NULL AUTO_INCREMENT,
  `sku` varchar(20) NOT NULL,
  `name` varchar(200) NOT NULL,
  `collection` varchar(100) NOT NULL,
  `price_chf` decimal(10,2) NOT NULL,
  `stock` int DEFAULT 0,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB;

INSERT INTO `products` VALUES
(1,'CV-IMP-001','Imperiale Grande Date','Imperiale',12400.00,24),
(2,'CV-IMP-002','Imperiale Moon Phase','Imperiale',18900.00,8),
(3,'CV-NAU-001','Nautique 300m','Nautique',8900.00,42),
(4,'CV-CAR-001','Carrée Squelette Rose Gold','Carrée',22800.00,6),
(5,'CV-TRB-001','Grande Tourbillon','Tourbillon',148000.00,2);

CREATE TABLE `orders` (
  `id` int NOT NULL AUTO_INCREMENT,
  `order_ref` varchar(20) NOT NULL,
  `customer_email` varchar(150) NOT NULL,
  `product_sku` varchar(20) NOT NULL,
  `total_chf` decimal(10,2) NOT NULL,
  `status` varchar(30) DEFAULT 'pending',
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB;

INSERT INTO `orders` VALUES
(1,'CHR-2024-00891','james.w@example.com','CV-NAU-001',8900.00,'shipped','2024-10-10 14:22:00'),
(2,'CHR-2024-00892','anna.k@example.com','CV-IMP-001',12400.00,'processing','2024-10-11 09:15:00'),
(3,'CHR-2024-00893','pierre.m@example.com','CV-TRB-001',148000.00,'pending','2024-10-14 16:40:00');
