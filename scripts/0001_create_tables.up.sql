-- Creating ENUMs
CREATE TYPE payment_status_enum AS ENUM ('pending', 'completed', 'failed');

-- Users Table
CREATE TABLE users
(
    id         SERIAL PRIMARY KEY,
    email      VARCHAR(255) UNIQUE NOT NULL,
    password   TEXT                NOT NULL,
    username   VARCHAR(50) UNIQUE  NOT NULL,
    first_name VARCHAR(50)         NOT NULL,
    last_name  VARCHAR(50)         NOT NULL
);

-- Seller Table
CREATE TABLE seller
(
    id           SERIAL PRIMARY KEY,
    email        VARCHAR(255) UNIQUE NOT NULL,
    password     TEXT                NOT NULL,
    rating       DECIMAL(3, 2) CHECK (rating >= 0 AND rating <= 5),
    review_count INT DEFAULT 0
);

-- Seller Address Table
CREATE TABLE seller_address
(
    id        SERIAL PRIMARY KEY,
    seller_id INT REFERENCES seller (id) ON DELETE CASCADE,
    street    VARCHAR(255) NOT NULL,
    city      VARCHAR(100) NOT NULL,
    state     VARCHAR(100) NOT NULL,
    country   VARCHAR(100) NOT NULL,
    zip       VARCHAR(20)  NOT NULL
);

-- Products Table
CREATE TABLE products
(
    id                      SERIAL PRIMARY KEY,
    name                    VARCHAR(255)   NOT NULL,
    price                   DECIMAL(10, 2) NOT NULL,
    in_stock                INT CHECK (in_stock >= 0),
    weight                  DECIMAL(10, 2),
    length                  DECIMAL(10, 2),
    breadth                 DECIMAL(10, 2),
    height                  DECIMAL(10, 2),
    tax_percentage          DECIMAL(5, 2) CHECK (tax_percentage >= 0),
    is_refundable           BOOLEAN DEFAULT FALSE,
    is_replacement_eligible BOOLEAN DEFAULT FALSE,
    sold_by                 INT REFERENCES seller (id) ON DELETE CASCADE,
    release_date            DATE,
    details                 JSONB
);

-- Cart Products Table
CREATE TABLE cart_products
(
    user_id    INT REFERENCES users (id) ON DELETE CASCADE,
    product_id INT REFERENCES products (id) ON DELETE CASCADE,
    quantity   INT CHECK (quantity > 0),
    PRIMARY KEY (user_id, product_id)
);

-- Orders Table
CREATE TABLE orders
(
    id                     SERIAL PRIMARY KEY,
    user_id                INT            REFERENCES users (id) ON DELETE SET NULL,
    payment_status         payment_status_enum DEFAULT 'pending',
    total_amount           DECIMAL(10, 2) NOT NULL,
    order_date             TIMESTAMP           DEFAULT CURRENT_TIMESTAMP,
    est_delivery_date      DATE,
    payment_initiated_date TIMESTAMP,
    payment_completed_date TIMESTAMP
);

-- Order Products Table
CREATE TABLE order_products
(
    order_id     INT REFERENCES orders (id) ON DELETE CASCADE,
    product_id   INT REFERENCES products (id) ON DELETE CASCADE,
    quantity     INT CHECK (quantity > 0),
    unit_price   DECIMAL(10, 2) NOT NULL,
    total_price  DECIMAL(10, 2) NOT NULL,
    is_delivered BOOLEAN DEFAULT FALSE,
    PRIMARY KEY (order_id, product_id)
);

-- Customer Address Table
CREATE TABLE customer_address
(
    id              SERIAL PRIMARY KEY,
    user_id         INT REFERENCES users (id) ON DELETE CASCADE,
    is_default_addr BOOLEAN DEFAULT FALSE,
    street          VARCHAR(255) NOT NULL,
    city            VARCHAR(100) NOT NULL,
    state           VARCHAR(100) NOT NULL,
    country         VARCHAR(100) NOT NULL,
    zip             VARCHAR(20)  NOT NULL
);

-- Delivery Table
CREATE TABLE delivery
(
    id                       SERIAL PRIMARY KEY,
    order_id                 INT REFERENCES orders (id) ON DELETE CASCADE,
    product_ids              INT[] NOT NULL,
    delivery_initiated_date  TIMESTAMP,
    delivery_completion_date TIMESTAMP,
    customer_address_id      INT REFERENCES customer_address (id) ON DELETE SET NULL
);



-- Payment Table
CREATE TABLE payment
(
    id                   SERIAL PRIMARY KEY,
    order_id             INT REFERENCES orders (id) ON DELETE CASCADE,
    transaction_id       VARCHAR(255) UNIQUE NOT NULL,
    is_gift_card_applied BOOLEAN DEFAULT FALSE,
    payable_amount       DECIMAL(10, 2)      NOT NULL
);

-- Gift Cards Table
CREATE TABLE gift_cards
(
    id         SERIAL PRIMARY KEY,
    code       VARCHAR(50) UNIQUE NOT NULL,
    amount     DECIMAL(10, 2)     NOT NULL CHECK (amount >= 0),
    is_claimed BOOLEAN DEFAULT FALSE,
    claimed_at TIMESTAMP
);

-- Indexes for optimization
CREATE INDEX idx_user_email ON users (email);
CREATE INDEX idx_seller_email ON seller (email);
CREATE INDEX idx_product_name ON products (name);
CREATE INDEX idx_orders_user ON orders (user_id);
CREATE INDEX idx_order_status ON orders (payment_status);
