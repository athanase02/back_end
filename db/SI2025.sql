-- ============================================================
-- SwapIt Database Schema
-- Database: SI2025 (SwapIt 2025)
-- 
-- A complete peer-to-peer item borrowing and lending platform
-- Features: User accounts, item listings, borrowing/swapping,
--           reviews, messaging, wishlists, notifications,
--           transaction history, and administrative features
-- ============================================================

-- Drop database if exists and create new one
DROP DATABASE IF EXISTS SI2025;
CREATE DATABASE SI2025;
USE SI2025;

-- ============================================================
-- SECTION 1: USER MANAGEMENT TABLES
-- ============================================================

-- Users table - Core authentication and user data
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    avatar_url TEXT,
    phone VARCHAR(20),
    is_verified BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    account_type ENUM('student', 'staff', 'admin') DEFAULT 'student',
    email_verified_at TIMESTAMP NULL,
    last_login_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_email (email),
    INDEX idx_account_type (account_type)
);

-- User profiles - Extended user information
CREATE TABLE profiles (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL UNIQUE,
    full_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    phone VARCHAR(20),
    bio TEXT,
    avatar_url TEXT,
    location VARCHAR(255),
    university VARCHAR(255) DEFAULT 'Ashesi University',
    student_id VARCHAR(50),
    graduation_year INT,
    rating_average DECIMAL(3,2) DEFAULT 5.00,
    total_reviews INT DEFAULT 0,
    total_items_listed INT DEFAULT 0,
    total_items_borrowed INT DEFAULT 0,
    total_items_lent INT DEFAULT 0,
    trust_score INT DEFAULT 100,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_rating (rating_average),
    INDEX idx_user_id (user_id)
);

-- User verification tokens for email verification and password reset
CREATE TABLE verification_tokens (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    token_type ENUM('email_verification', 'password_reset', 'two_factor') NOT NULL,
    expires_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_token (token),
    INDEX idx_user_token (user_id, token_type)
);

-- User sessions for tracking active logins
CREATE TABLE user_sessions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    session_token VARCHAR(255) NOT NULL UNIQUE,
    ip_address VARCHAR(45),
    user_agent TEXT,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_token (session_token),
    INDEX idx_user_id (user_id)
);

-- ============================================================
-- SECTION 2: ITEM MANAGEMENT TABLES
-- ============================================================

-- Categories for organizing items
CREATE TABLE categories (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL UNIQUE,
    slug VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    icon VARCHAR(50),
    parent_id INT NULL,
    display_order INT DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (parent_id) REFERENCES categories(id) ON DELETE SET NULL,
    INDEX idx_slug (slug),
    INDEX idx_parent (parent_id)
);

-- Items/listings table - Main inventory
CREATE TABLE items (
    id INT PRIMARY KEY AUTO_INCREMENT,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    category_id INT NOT NULL,
    condition_status ENUM('New', 'Like New', 'Good', 'Fair', 'Poor') NOT NULL,
    price DECIMAL(10,2) NOT NULL COMMENT 'Borrowing price per day/week',
    rental_period ENUM('hourly', 'daily', 'weekly', 'monthly') DEFAULT 'daily',
    location VARCHAR(255) NOT NULL,
    latitude DECIMAL(10, 8),
    longitude DECIMAL(11, 8),
    image_urls JSON COMMENT 'Array of image URLs',
    owner_id INT NOT NULL,
    status ENUM('available', 'borrowed', 'pending', 'unavailable', 'deleted') DEFAULT 'available',
    views INT DEFAULT 0,
    saves_count INT DEFAULT 0,
    borrow_count INT DEFAULT 0,
    is_featured BOOLEAN DEFAULT FALSE,
    featured_until TIMESTAMP NULL,
    tags JSON COMMENT 'Array of searchable tags',
    availability_notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (category_id) REFERENCES categories(id),
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_status (status),
    INDEX idx_owner (owner_id),
    INDEX idx_category (category_id),
    INDEX idx_price (price),
    INDEX idx_featured (is_featured, featured_until),
    FULLTEXT idx_search (title, description)
);

-- Item images - Multiple images per item
CREATE TABLE item_images (
    id INT PRIMARY KEY AUTO_INCREMENT,
    item_id INT NOT NULL,
    image_url TEXT NOT NULL,
    is_primary BOOLEAN DEFAULT FALSE,
    display_order INT DEFAULT 0,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE CASCADE,
    INDEX idx_item (item_id),
    INDEX idx_primary (item_id, is_primary)
);

-- ============================================================
-- SECTION 3: TRANSACTION TABLES
-- ============================================================

-- Borrow/swap requests (formerly swap_requests)
CREATE TABLE borrow_requests (
    id INT PRIMARY KEY AUTO_INCREMENT,
    item_id INT NOT NULL,
    borrower_id INT NOT NULL,
    lender_id INT NOT NULL,
    status ENUM('pending', 'accepted', 'rejected', 'active', 'completed', 'cancelled', 'disputed') DEFAULT 'pending',
    borrow_start_date DATETIME NOT NULL,
    borrow_end_date DATETIME NOT NULL,
    actual_return_date DATETIME NULL,
    total_price DECIMAL(10,2) NOT NULL,
    security_deposit DECIMAL(10,2) DEFAULT 0.00,
    pickup_location VARCHAR(255),
    return_location VARCHAR(255),
    borrower_message TEXT,
    lender_notes TEXT,
    cancellation_reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE CASCADE,
    FOREIGN KEY (borrower_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (lender_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_status (status),
    INDEX idx_borrower (borrower_id),
    INDEX idx_lender (lender_id),
    INDEX idx_item (item_id),
    INDEX idx_dates (borrow_start_date, borrow_end_date)
);

-- Transaction history for financial tracking
CREATE TABLE transactions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    borrow_request_id INT NOT NULL,
    payer_id INT NOT NULL,
    payee_id INT NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    transaction_type ENUM('rental_payment', 'security_deposit', 'deposit_refund', 'late_fee', 'damage_fee') NOT NULL,
    payment_method ENUM('cash', 'mobile_money', 'card', 'bank_transfer') DEFAULT 'cash',
    payment_status ENUM('pending', 'completed', 'failed', 'refunded') DEFAULT 'pending',
    payment_reference VARCHAR(255),
    notes TEXT,
    processed_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (borrow_request_id) REFERENCES borrow_requests(id) ON DELETE CASCADE,
    FOREIGN KEY (payer_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (payee_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_request (borrow_request_id),
    INDEX idx_payer (payer_id),
    INDEX idx_payee (payee_id),
    INDEX idx_status (payment_status)
);

-- Shopping cart for multiple item borrowing
CREATE TABLE cart_items (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    item_id INT NOT NULL,
    start_date DATETIME NOT NULL,
    end_date DATETIME NOT NULL,
    quantity INT DEFAULT 1,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE CASCADE,
    UNIQUE KEY unique_cart_item (user_id, item_id),
    INDEX idx_user (user_id)
);

-- ============================================================
-- SECTION 4: SOCIAL FEATURES TABLES
-- ============================================================

-- Wishlist/Saved items
CREATE TABLE saved_items (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    item_id INT NOT NULL,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE CASCADE,
    UNIQUE KEY unique_saved_item (user_id, item_id),
    INDEX idx_user (user_id)
);

-- User ratings and reviews
CREATE TABLE reviews (
    id INT PRIMARY KEY AUTO_INCREMENT,
    reviewer_id INT NOT NULL,
    reviewed_user_id INT NOT NULL,
    borrow_request_id INT NOT NULL,
    rating INT NOT NULL CHECK (rating >= 1 AND rating <= 5),
    review_type ENUM('borrower_to_lender', 'lender_to_borrower') NOT NULL,
    title VARCHAR(255),
    comment TEXT,
    is_anonymous BOOLEAN DEFAULT FALSE,
    helpful_count INT DEFAULT 0,
    reported_count INT DEFAULT 0,
    is_verified_borrow BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (reviewer_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (reviewed_user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (borrow_request_id) REFERENCES borrow_requests(id) ON DELETE CASCADE,
    UNIQUE KEY unique_review (reviewer_id, borrow_request_id, review_type),
    INDEX idx_reviewed_user (reviewed_user_id),
    INDEX idx_rating (rating)
);

-- Review helpful votes
CREATE TABLE review_votes (
    id INT PRIMARY KEY AUTO_INCREMENT,
    review_id INT NOT NULL,
    user_id INT NOT NULL,
    vote_type ENUM('helpful', 'not_helpful') NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (review_id) REFERENCES reviews(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_vote (review_id, user_id)
);

-- Messages between users
CREATE TABLE messages (
    id INT PRIMARY KEY AUTO_INCREMENT,
    conversation_id INT NOT NULL,
    sender_id INT NOT NULL,
    receiver_id INT NOT NULL,
    item_id INT,
    message_text TEXT NOT NULL,
    attachment_url TEXT,
    is_read BOOLEAN DEFAULT FALSE,
    read_at TIMESTAMP NULL,
    is_deleted_by_sender BOOLEAN DEFAULT FALSE,
    is_deleted_by_receiver BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE SET NULL,
    INDEX idx_conversation (conversation_id),
    INDEX idx_sender (sender_id),
    INDEX idx_receiver (receiver_id),
    INDEX idx_read (is_read)
);

-- Conversations - Group messages between two users
CREATE TABLE conversations (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user1_id INT NOT NULL,
    user2_id INT NOT NULL,
    item_id INT,
    last_message_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user1_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (user2_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE SET NULL,
    UNIQUE KEY unique_conversation (user1_id, user2_id),
    INDEX idx_users (user1_id, user2_id),
    INDEX idx_last_message (last_message_at)
);

-- User follows/connections
CREATE TABLE user_follows (
    id INT PRIMARY KEY AUTO_INCREMENT,
    follower_id INT NOT NULL,
    following_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (follower_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (following_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_follow (follower_id, following_id),
    INDEX idx_follower (follower_id),
    INDEX idx_following (following_id)
);

-- ============================================================
-- SECTION 5: NOTIFICATION TABLES
-- ============================================================

-- User notifications
CREATE TABLE notifications (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    type ENUM('borrow_request', 'request_accepted', 'request_rejected', 'item_borrowed', 
              'return_reminder', 'return_confirmed', 'new_review', 'new_message', 
              'item_saved', 'price_drop', 'new_follower', 'system_announcement') NOT NULL,
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    related_id INT COMMENT 'ID of related entity (item, request, user, etc.)',
    action_url VARCHAR(500),
    is_read BOOLEAN DEFAULT FALSE,
    read_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_read (user_id, is_read),
    INDEX idx_created (created_at)
);

-- ============================================================
-- SECTION 6: ADMINISTRATIVE TABLES
-- ============================================================

-- Reported content for moderation
CREATE TABLE reports (
    id INT PRIMARY KEY AUTO_INCREMENT,
    reporter_id INT NOT NULL,
    reported_user_id INT,
    reported_item_id INT,
    reported_review_id INT,
    report_type ENUM('inappropriate_content', 'spam', 'fraud', 'harassment', 'fake_listing', 'other') NOT NULL,
    description TEXT NOT NULL,
    status ENUM('pending', 'reviewing', 'resolved', 'dismissed') DEFAULT 'pending',
    moderator_id INT,
    moderator_notes TEXT,
    action_taken ENUM('none', 'warning', 'content_removed', 'user_suspended', 'user_banned') DEFAULT 'none',
    resolved_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (reporter_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (reported_user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (reported_item_id) REFERENCES items(id) ON DELETE SET NULL,
    FOREIGN KEY (reported_review_id) REFERENCES reviews(id) ON DELETE SET NULL,
    FOREIGN KEY (moderator_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_status (status),
    INDEX idx_reporter (reporter_id)
);

-- System activity logs
CREATE TABLE activity_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(50),
    entity_id INT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    details JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_user (user_id),
    INDEX idx_action (action),
    INDEX idx_created (created_at)
);

-- Platform settings and configuration
CREATE TABLE site_settings (
    id INT PRIMARY KEY AUTO_INCREMENT,
    setting_key VARCHAR(100) NOT NULL UNIQUE,
    setting_value TEXT,
    setting_type ENUM('string', 'integer', 'boolean', 'json') DEFAULT 'string',
    description TEXT,
    is_public BOOLEAN DEFAULT FALSE,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_key (setting_key)
);

-- ============================================================
-- SECTION 7: INSERT SAMPLE DATA
-- ============================================================

-- Insert sample users
INSERT INTO users (email, password_hash, full_name, avatar_url, phone, is_verified, account_type, last_login_at) VALUES
('athanase.abayo@ashesi.edu.gh', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Athanase Abayo', 'https://i.pravatar.cc/150?img=12', '+233501234567', TRUE, 'student', NOW()),
('mabinty.mambu@ashesi.edu.gh', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Mabinty Mambu', 'https://i.pravatar.cc/150?img=5', '+233507654321', TRUE, 'student', NOW()),
('olivier.kwizera@ashesi.edu.gh', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Olivier Kwizera', 'https://i.pravatar.cc/150?img=33', '+233503456789', TRUE, 'student', NOW()),
('victoria.nyonato@ashesi.edu.gh', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Victoria Ama Nyonato', 'https://i.pravatar.cc/150?img=9', '+233509876543', TRUE, 'student', NOW()),
('admin@swapit.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'SwapIt Admin', 'https://i.pravatar.cc/150?img=60', '+233501111111', TRUE, 'admin', NOW()),
('kwame.mensah@ashesi.edu.gh', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Kwame Mensah', 'https://i.pravatar.cc/150?img=15', '+233502345678', TRUE, 'student', NOW()),
('ama.serwaa@ashesi.edu.gh', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Ama Serwaa', 'https://i.pravatar.cc/150?img=20', '+233508765432', TRUE, 'student', NOW()),
('kofi.annan@ashesi.edu.gh', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Kofi Annan', 'https://i.pravatar.cc/150?img=25', '+233505678901', TRUE, 'student', NOW());

-- Insert user profiles
INSERT INTO profiles (user_id, full_name, email, phone, bio, location, student_id, graduation_year, rating_average, total_items_listed, total_items_borrowed, total_items_lent) VALUES
(1, 'Athanase Abayo', 'athanase.abayo@ashesi.edu.gh', '+233501234567', 'Computer Science student passionate about sustainable living and tech innovation.', 'Berekuso Campus', 'A00012345', 2026, 4.85, 12, 8, 15),
(2, 'Mabinty Mambu', 'mabinty.mambu@ashesi.edu.gh', '+233507654321', 'Business Administration major. Love sharing and borrowing items within the community!', 'Berekuso Campus', 'A00023456', 2025, 4.92, 8, 12, 10),
(3, 'Olivier Kwizera', 'olivier.kwizera@ashesi.edu.gh', '+233503456789', 'Engineering student. Building a sustainable future one swap at a time.', 'Berekuso Campus', 'A00034567', 2026, 4.78, 15, 5, 18),
(4, 'Victoria Ama Nyonato', 'victoria.nyonato@ashesi.edu.gh', '+233509876543', 'MIS student. Believer in the sharing economy and community support.', 'Berekuso Campus', 'A00045678', 2027, 4.95, 6, 10, 8),
(5, 'SwapIt Admin', 'admin@swapit.com', '+233501111111', 'SwapIt platform administrator. Here to help with any issues!', 'Ashesi University', 'ADMIN001', NULL, 5.00, 0, 0, 0),
(6, 'Kwame Mensah', 'kwame.mensah@ashesi.edu.gh', '+233502345678', 'Economics major. Always looking for good deals and interesting items.', 'Berekuso Campus', 'A00056789', 2025, 4.67, 10, 15, 12),
(7, 'Ama Serwaa', 'ama.serwaa@ashesi.edu.gh', '+233508765432', 'Art & Design student. Love vintage items and unique finds.', 'Berekuso Campus', 'A00067890', 2026, 4.88, 14, 7, 16),
(8, 'Kofi Annan', 'kofi.annan@ashesi.edu.gh', '+233505678901', 'Political Science student. Sustainable living advocate.', 'Berekuso Campus', 'A00078901', 2027, 4.73, 9, 11, 11);

-- Insert categories
INSERT INTO categories (name, slug, description, icon, parent_id, display_order, is_active) VALUES
('Books & Textbooks', 'books-textbooks', 'Textbooks, novels, academic materials, and other reading materials', 'fa-book', NULL, 1, TRUE),
('Electronics', 'electronics', 'Phones, laptops, tablets, chargers, and other electronic devices', 'fa-laptop', NULL, 2, TRUE),
('Furniture', 'furniture', 'Chairs, tables, beds, storage units, and other furniture items', 'fa-couch', NULL, 3, TRUE),
('Clothing & Fashion', 'clothing-fashion', 'Clothes, shoes, accessories, and fashion items', 'fa-shirt', NULL, 4, TRUE),
('Sports Equipment', 'sports-equipment', 'Sports gear, exercise equipment, and outdoor activities', 'fa-dumbbell', NULL, 5, TRUE),
('School Supplies', 'school-supplies', 'Notebooks, stationery, calculators, and other academic materials', 'fa-pen', NULL, 6, TRUE),
('Musical Instruments', 'musical-instruments', 'Guitars, keyboards, drums, and other musical instruments', 'fa-music', NULL, 7, TRUE),
('Art Supplies', 'art-supplies', 'Paint, canvas, brushes, and other art materials', 'fa-palette', NULL, 8, TRUE),
('Kitchen & Appliances', 'kitchen-appliances', 'Utensils, appliances, cookware, and kitchen items', 'fa-kitchen-set', NULL, 9, TRUE),
('Photography', 'photography', 'Cameras, lenses, tripods, and photography equipment', 'fa-camera', NULL, 10, TRUE),
('Gaming', 'gaming', 'Consoles, games, controllers, and gaming accessories', 'fa-gamepad', NULL, 11, TRUE),
('Tools & Hardware', 'tools-hardware', 'Power tools, hand tools, and hardware equipment', 'fa-wrench', NULL, 12, TRUE),
('Party Supplies', 'party-supplies', 'Decorations, sound systems, and party equipment', 'fa-cake-candles', NULL, 13, TRUE),
('Travel Gear', 'travel-gear', 'Suitcases, backpacks, and travel accessories', 'fa-suitcase', NULL, 14, TRUE),
('Other', 'other', 'Miscellaneous items that don\'t fit other categories', 'fa-ellipsis', NULL, 15, TRUE);

-- Insert sample items
INSERT INTO items (title, description, category_id, condition_status, price, rental_period, location, owner_id, status, views, saves_count, borrow_count, tags) VALUES
('Introduction to Algorithms (3rd Edition)', 'Classic computer science textbook by Cormen. Perfect for CS students. Well-maintained with minimal highlighting.', 1, 'Good', 5.00, 'weekly', 'Berekuso Campus - Main Library', 1, 'available', 45, 12, 8, '["algorithms", "computer science", "textbook", "programming"]'),
('MacBook Pro 2020 (M1)', 'Apple MacBook Pro with M1 chip, 16GB RAM, 512GB SSD. Perfect for software development and design work.', 2, 'Like New', 25.00, 'daily', 'Berekuso Campus - Tech Lab', 3, 'available', 89, 25, 3, '["laptop", "macbook", "apple", "programming", "design"]'),
('Study Desk with Chair', 'Sturdy wooden desk with comfortable office chair. Great for late-night study sessions.', 3, 'Good', 3.00, 'weekly', 'Berekuso Campus - Residence Hall A', 2, 'available', 34, 8, 5, '["furniture", "desk", "chair", "study"]'),
('Canon EOS 90D DSLR Camera', 'Professional DSLR camera with 18-135mm lens. Perfect for events, portraits, and photography projects.', 10, 'Like New', 20.00, 'daily', 'Berekuso Campus - Media Center', 4, 'available', 67, 18, 6, '["camera", "photography", "dslr", "canon"]'),
('Organic Chemistry Textbook', 'McMurry\'s Organic Chemistry, 9th edition. Essential for chemistry majors. Clean condition.', 1, 'Good', 4.00, 'weekly', 'Berekuso Campus - Science Block', 6, 'available', 28, 7, 4, '["chemistry", "textbook", "organic chemistry", "science"]'),
('Electric Guitar with Amp', 'Fender Stratocaster electric guitar with portable amplifier. Perfect for practice or small gigs.', 7, 'Good', 8.00, 'daily', 'Berekuso Campus - Music Room', 7, 'available', 52, 15, 7, '["guitar", "music", "instrument", "electric"]'),
('PlayStation 5 Console', 'Sony PS5 with 2 controllers and popular games. Great for gaming sessions with friends.', 11, 'Like New', 15.00, 'daily', 'Berekuso Campus - Recreation Center', 8, 'borrowed', 156, 42, 12, '["gaming", "playstation", "ps5", "console", "entertainment"]'),
('Scientific Calculator (TI-84)', 'Texas Instruments TI-84 Plus graphing calculator. Essential for math and engineering courses.', 6, 'Good', 2.00, 'weekly', 'Berekuso Campus - Academic Block', 1, 'available', 41, 9, 11, '["calculator", "mathematics", "graphing", "school supplies"]'),
('Portable Bluetooth Speaker', 'JBL Flip 5 waterproof speaker. Perfect for beach trips, parties, or outdoor hangouts.', 2, 'Like New', 3.00, 'daily', 'Berekuso Campus - Student Center', 3, 'available', 38, 11, 8, '["speaker", "bluetooth", "music", "party", "portable"]'),
('Professional Easel & Canvas Set', 'Adjustable wooden easel with assorted canvas sizes. Ideal for art projects and painting.', 8, 'Good', 4.00, 'weekly', 'Berekuso Campus - Art Studio', 7, 'available', 22, 6, 3, '["art", "painting", "easel", "canvas"]'),
('Road Bike (21-Speed)', 'Lightweight aluminum road bike in excellent condition. Perfect for campus commuting or weekend rides.', 5, 'Good', 5.00, 'daily', 'Berekuso Campus - Sports Complex', 6, 'available', 47, 13, 9, '["bicycle", "sports", "fitness", "transportation"]'),
('KitchenAid Stand Mixer', 'Professional stand mixer for baking enthusiasts. Comes with multiple attachments.', 9, 'Like New', 6.00, 'weekly', 'Berekuso Campus - Residence Hall C', 2, 'available', 31, 8, 5, '["kitchen", "baking", "appliance", "cooking"]'),
('Camping Tent (4-Person)', 'Spacious waterproof tent perfect for weekend camping trips. Easy to set up.', 14, 'Good', 7.00, 'weekly', 'Berekuso Campus - Outdoor Center', 8, 'available', 29, 7, 4, '["camping", "outdoor", "tent", "travel"]'),
('MIDI Keyboard Controller', '61-key MIDI keyboard for music production. Compatible with all major DAWs.', 7, 'Like New', 6.00, 'weekly', 'Berekuso Campus - Music Studio', 4, 'available', 35, 10, 5, '["music", "midi", "keyboard", "production"]'),
('Wireless Drill Set', 'DeWalt cordless drill with multiple bits and carrying case. Perfect for DIY projects.', 12, 'Good', 5.00, 'daily', 'Berekuso Campus - Engineering Lab', 3, 'available', 26, 5, 6, '["tools", "drill", "diy", "hardware"]');

-- Insert item images
INSERT INTO item_images (item_id, image_url, is_primary, display_order) VALUES
(1, 'https://images.unsplash.com/photo-1544947950-fa07a98d237f?w=400', TRUE, 1),
(2, 'https://images.unsplash.com/photo-1517336714731-489689fd1ca8?w=400', TRUE, 1),
(3, 'https://images.unsplash.com/photo-1518455027359-f3f8164ba6bd?w=400', TRUE, 1),
(4, 'https://images.unsplash.com/photo-1502920917128-1aa500764cbd?w=400', TRUE, 1),
(5, 'https://images.unsplash.com/photo-1532012197267-da84d127e765?w=400', TRUE, 1),
(6, 'https://images.unsplash.com/photo-1510915361894-db8b60106cb1?w=400', TRUE, 1),
(7, 'https://images.unsplash.com/photo-1606144042614-b2417e99c4e3?w=400', TRUE, 1),
(8, 'https://images.unsplash.com/photo-1611251135414-559ca71c60d7?w=400', TRUE, 1),
(9, 'https://images.unsplash.com/photo-1608043152269-423dbba4e7e1?w=400', TRUE, 1),
(10, 'https://images.unsplash.com/photo-1513519245088-0e12902e35ca?w=400', TRUE, 1);

-- Insert borrow requests
INSERT INTO borrow_requests (item_id, borrower_id, lender_id, status, borrow_start_date, borrow_end_date, total_price, security_deposit, pickup_location, borrower_message) VALUES
(7, 2, 8, 'active', '2025-11-25 14:00:00', '2025-11-30 14:00:00', 75.00, 50.00, 'Berekuso Campus - Recreation Center', 'Need it for weekend gaming session with friends. Will take good care of it!'),
(2, 6, 3, 'completed', '2025-11-15 09:00:00', '2025-11-18 09:00:00', 75.00, 100.00, 'Berekuso Campus - Tech Lab', 'Need for final year project presentation.'),
(1, 4, 1, 'pending', '2025-12-01 08:00:00', '2025-12-08 08:00:00', 5.00, 10.00, 'Berekuso Campus - Main Library', 'Preparing for algorithms exam. Really need this book!'),
(4, 7, 4, 'accepted', '2025-11-28 10:00:00', '2025-11-29 18:00:00', 40.00, 200.00, 'Berekuso Campus - Media Center', 'Photography project for class. Will handle with care.'),
(6, 2, 7, 'completed', '2025-11-20 15:00:00', '2025-11-22 15:00:00', 16.00, 50.00, 'Berekuso Campus - Music Room', 'Band practice for talent show.');

-- Insert transactions
INSERT INTO transactions (borrow_request_id, payer_id, payee_id, amount, transaction_type, payment_method, payment_status, processed_at) VALUES
(1, 2, 8, 75.00, 'rental_payment', 'mobile_money', 'completed', '2025-11-25 13:45:00'),
(1, 2, 8, 50.00, 'security_deposit', 'mobile_money', 'completed', '2025-11-25 13:45:00'),
(2, 6, 3, 75.00, 'rental_payment', 'mobile_money', 'completed', '2025-11-15 08:30:00'),
(2, 6, 3, 100.00, 'security_deposit', 'mobile_money', 'completed', '2025-11-15 08:30:00'),
(2, 3, 6, 100.00, 'deposit_refund', 'mobile_money', 'completed', '2025-11-18 10:00:00'),
(5, 2, 7, 16.00, 'rental_payment', 'cash', 'completed', '2025-11-20 14:30:00');

-- Insert saved/wishlist items
INSERT INTO saved_items (user_id, item_id, notes) VALUES
(2, 2, 'Might need for next semester project'),
(2, 4, 'Want to try photography'),
(4, 1, 'Need this book for next semester'),
(6, 6, 'Learning to play guitar'),
(7, 9, 'For upcoming beach trip'),
(1, 7, 'Gaming weekend planned'),
(3, 11, 'Want to start cycling'),
(8, 13, 'Planning camping trip');

-- Insert reviews
INSERT INTO reviews (reviewer_id, reviewed_user_id, borrow_request_id, rating, review_type, title, comment, is_verified_borrow) VALUES
(6, 3, 2, 5, 'borrower_to_lender', 'Excellent Lender!', 'Olivier was very professional and the MacBook was in perfect condition. Great communication throughout. Highly recommend!', TRUE),
(3, 6, 2, 5, 'lender_to_borrower', 'Responsible Borrower', 'Kwame returned the laptop on time and in perfect condition. Very trustworthy!', TRUE),
(2, 7, 5, 5, 'borrower_to_lender', 'Great Experience', 'Guitar was in amazing condition. Ama was very helpful with setup tips. Will definitely borrow again!', TRUE),
(7, 2, 5, 5, 'lender_to_borrower', 'Perfect Borrower', 'Mabinty took excellent care of my guitar. Returned it even cleaner than I gave it!', TRUE),
(2, 8, 1, 4, 'borrower_to_lender', 'Good Console, Good Owner', 'PS5 works perfectly. Kofi was responsive and helpful. Only minor issue was pickup timing.', TRUE);

-- Insert cart items
INSERT INTO cart_items (user_id, item_id, start_date, end_date, quantity) VALUES
(4, 8, '2025-12-05 09:00:00', '2025-12-12 09:00:00', 1),
(4, 5, '2025-12-05 09:00:00', '2025-12-12 09:00:00', 1),
(6, 9, '2025-12-01 14:00:00', '2025-12-03 14:00:00', 1);

-- Insert notifications
INSERT INTO notifications (user_id, type, title, message, related_id, is_read) VALUES
(1, 'borrow_request', 'New Borrow Request', 'Victoria wants to borrow your "Introduction to Algorithms" textbook', 3, FALSE),
(4, 'request_accepted', 'Request Accepted!', 'Your request to borrow the Canon EOS 90D has been accepted by Victoria', 4, FALSE),
(8, 'return_reminder', 'Return Reminder', 'Your rental of PlayStation 5 Console ends tomorrow. Please arrange return.', 1, FALSE),
(3, 'new_review', 'You Received a Review', 'Kwame left you a 5-star review for the MacBook rental', 2, TRUE),
(2, 'new_message', 'New Message', 'You have a new message from Kofi Annan about PS5', 1, FALSE);

-- Insert conversations
INSERT INTO conversations (user1_id, user2_id, item_id, last_message_at) VALUES
(2, 8, 7, '2025-11-25 13:30:00'),
(6, 3, 2, '2025-11-15 08:00:00'),
(4, 1, 1, '2025-11-29 10:15:00'),
(7, 4, 4, '2025-11-28 09:45:00');

-- Insert messages
INSERT INTO messages (conversation_id, sender_id, receiver_id, item_id, message_text, is_read, read_at) VALUES
(1, 2, 8, 7, 'Hi! Is the PS5 still available for this weekend?', TRUE, '2025-11-25 13:15:00'),
(1, 8, 2, 7, 'Yes, it is! When do you need it?', TRUE, '2025-11-25 13:20:00'),
(1, 2, 8, 7, 'Perfect! Can I pick it up Friday afternoon?', TRUE, '2025-11-25 13:25:00'),
(1, 8, 2, 7, 'Sure! Let me know when you arrive at the rec center.', TRUE, '2025-11-25 13:30:00'),
(3, 4, 1, 1, 'Hello! I really need this book for my exam prep. Is it available next week?', FALSE, NULL);

-- Insert site settings
INSERT INTO site_settings (setting_key, setting_value, setting_type, description, is_public) VALUES
('site_name', 'SwapIt', 'string', 'Platform name', TRUE),
('site_tagline', 'Shop, Swap, and Save Together', 'string', 'Platform tagline', TRUE),
('max_borrow_days', '30', 'integer', 'Maximum borrowing period in days', TRUE),
('late_fee_per_day', '2.00', 'string', 'Late fee charged per day after return date', TRUE),
('security_deposit_percentage', '50', 'integer', 'Security deposit as percentage of rental price', FALSE),
('platform_commission', '10', 'integer', 'Platform commission percentage', FALSE),
('min_trust_score', '50', 'integer', 'Minimum trust score to borrow items', TRUE),
('support_email', 'support@swapit.com', 'string', 'Support contact email', TRUE);

-- Insert activity logs (recent user actions)
INSERT INTO activity_logs (user_id, action, entity_type, entity_id, ip_address, details) VALUES
(2, 'borrow_request_created', 'borrow_request', 1, '192.168.1.100', '{"item_id": 7, "amount": 75.00}'),
(4, 'item_saved', 'item', 1, '192.168.1.101', '{"item_title": "Introduction to Algorithms"}'),
(6, 'review_posted', 'review', 1, '192.168.1.102', '{"rating": 5, "reviewed_user": 3}'),
(7, 'item_listed', 'item', 6, '192.168.1.103', '{"title": "Electric Guitar with Amp"}'),
(8, 'borrow_request_accepted', 'borrow_request', 1, '192.168.1.104', '{"borrower_id": 2}');

-- ============================================================
-- SECTION 8: USEFUL VIEWS FOR COMMON QUERIES
-- ============================================================

-- View: Active listings with owner information
CREATE VIEW active_listings AS
SELECT 
    i.id,
    i.title,
    i.description,
    i.price,
    i.rental_period,
    i.location,
    i.condition_status,
    i.views,
    i.saves_count,
    c.name as category_name,
    u.full_name as owner_name,
    u.email as owner_email,
    p.rating_average as owner_rating,
    i.created_at
FROM items i
JOIN categories c ON i.category_id = c.id
JOIN users u ON i.owner_id = u.id
JOIN profiles p ON u.id = p.user_id
WHERE i.status = 'available'
ORDER BY i.created_at DESC;

-- View: User statistics dashboard
CREATE VIEW user_dashboard_stats AS
SELECT 
    u.id as user_id,
    u.full_name,
    u.email,
    p.rating_average,
    p.total_reviews,
    COUNT(DISTINCT CASE WHEN i.status = 'available' THEN i.id END) as active_listings,
    COUNT(DISTINCT CASE WHEN br.borrower_id = u.id THEN br.id END) as total_borrows,
    COUNT(DISTINCT CASE WHEN br.lender_id = u.id AND br.status = 'completed' THEN br.id END) as items_lent,
    COALESCE(SUM(CASE WHEN t.payee_id = u.id AND t.payment_status = 'completed' THEN t.amount END), 0) as total_earnings
FROM users u
JOIN profiles p ON u.id = p.user_id
LEFT JOIN items i ON u.id = i.owner_id
LEFT JOIN borrow_requests br ON u.id = br.borrower_id OR u.id = br.lender_id
LEFT JOIN transactions t ON br.id = t.borrow_request_id
GROUP BY u.id, u.full_name, u.email, p.rating_average, p.total_reviews;

-- ============================================================
-- SECTION 9: INDEXES FOR PERFORMANCE OPTIMIZATION
-- ============================================================

-- Additional composite indexes for common queries
CREATE INDEX idx_items_status_category ON items(status, category_id);
CREATE INDEX idx_items_owner_status ON items(owner_id, status);
CREATE INDEX idx_borrow_dates ON borrow_requests(borrow_start_date, borrow_end_date, status);
CREATE INDEX idx_messages_conversation_created ON messages(conversation_id, created_at);
CREATE INDEX idx_notifications_user_created ON notifications(user_id, created_at DESC);

-- ============================================================
-- SUCCESS MESSAGE
-- ============================================================

SELECT 'SwapIt Database (SI2025) created successfully!' as status,
       (SELECT COUNT(*) FROM users) as total_users,
       (SELECT COUNT(*) FROM items) as total_items,
       (SELECT COUNT(*) FROM borrow_requests) as total_requests,
       (SELECT COUNT(*) FROM reviews) as total_reviews,
       (SELECT COUNT(*) FROM categories) as total_categories;

-- Add Google OAuth support to users table
-- This migration adds the google_id column to store Google account IDs

ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id VARCHAR(255) NULL UNIQUE AFTER email;

-- Add index for faster Google ID lookups
CREATE INDEX IF NOT EXISTS idx_google_id ON users(google_id);

-- Update existing users without google_id (optional)
-- This is safe to run multiple times
UPDATE users SET google_id = NULL WHERE google_id = '';
