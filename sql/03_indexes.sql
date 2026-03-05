-- =====================================================
-- LOBBYBETS KENYA - INDEXES
-- =====================================================
-- Run AFTER 02_seed_data.sql
-- =====================================================

\echo 'Creating indexes for performance...'

-- Profiles indexes
CREATE INDEX IF NOT EXISTS idx_profiles_phone ON profiles(phone);
CREATE INDEX IF NOT EXISTS idx_profiles_email ON profiles(email);
CREATE INDEX IF NOT EXISTS idx_profiles_referral_code ON profiles(referral_code);
CREATE INDEX IF NOT EXISTS idx_profiles_kyc_status ON profiles(kyc_status);
CREATE INDEX IF NOT EXISTS idx_profiles_created_at ON profiles(created_at);

-- Wallets indexes
CREATE INDEX IF NOT EXISTS idx_wallets_user_id ON wallets(user_id);
CREATE INDEX IF NOT EXISTS idx_wallets_last_updated ON wallets(last_updated);

-- Bets indexes
CREATE INDEX IF NOT EXISTS idx_bets_user_id ON bets(user_id);
CREATE INDEX IF NOT EXISTS idx_bets_status ON bets(status);
CREATE INDEX IF NOT EXISTS idx_bets_created_at ON bets(created_at);
CREATE INDEX IF NOT EXISTS idx_bets_user_status ON bets(user_id, status);

-- Transactions indexes
CREATE INDEX IF NOT EXISTS idx_transactions_user_id ON transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status);
CREATE INDEX IF NOT EXISTS idx_transactions_type ON transactions(type);
CREATE INDEX IF NOT EXISTS idx_transactions_created_at ON transactions(created_at);
CREATE INDEX IF NOT EXISTS idx_transactions_reference ON transactions(reference);

-- M-PESA transactions indexes
CREATE INDEX IF NOT EXISTS idx_mpesa_user_id ON mpesa_transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_mpesa_status ON mpesa_transactions(status);
CREATE INDEX IF NOT EXISTS idx_mpesa_checkout_request ON mpesa_transactions(checkout_request_id);
CREATE INDEX IF NOT EXISTS idx_mpesa_receipt ON mpesa_transactions(mpesa_receipt_number);

-- Matches indexes
CREATE INDEX IF NOT EXISTS idx_matches_league_id ON matches(league_id);
CREATE INDEX IF NOT EXISTS idx_matches_date ON matches(match_date);
CREATE INDEX IF NOT EXISTS idx_matches_status ON matches(status);

-- Notifications indexes
CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id);
CREATE INDEX IF NOT EXISTS idx_notifications_is_read ON notifications(is_read);
CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications(created_at);

\echo '✅ Indexes created successfully!'
