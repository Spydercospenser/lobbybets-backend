-- =====================================================
-- LOBBYBETS KENYA - ROW LEVEL SECURITY POLICIES
-- =====================================================
-- Run AFTER 05_views.sql
-- =====================================================

\echo 'Setting up Row Level Security policies...'

-- Enable RLS on tables
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE wallets ENABLE ROW LEVEL SECURITY;
ALTER TABLE bets ENABLE ROW LEVEL SECURITY;
ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE mpesa_transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;

-- Profiles policies
CREATE POLICY "Users can view own profile"
  ON profiles FOR SELECT
  USING (current_user = 'postgres' OR current_user = (SELECT current_user));

CREATE POLICY "Users can update own profile"
  ON profiles FOR UPDATE
  USING (current_user = 'postgres' OR current_user = (SELECT current_user));

-- Public access for leagues and matches
CREATE POLICY "Public can view leagues"
  ON leagues FOR SELECT
  USING (true);

CREATE POLICY "Public can view matches"
  ON matches FOR SELECT
  USING (true);

\echo '✅ Row Level Security policies created successfully!'
