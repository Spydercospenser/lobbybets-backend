-- =====================================================
-- LOBBYBETS KENYA - COMPLETE DATABASE SCHEMA
-- =====================================================
-- Run AFTER 00_setup.sql
-- =====================================================

\echo 'Creating tables...'

-- 1. PROFILES TABLE
CREATE TABLE IF NOT EXISTS profiles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  phone TEXT UNIQUE NOT NULL,
  full_name TEXT NOT NULL,
  email TEXT UNIQUE,
  age INTEGER CHECK (age >= 18),
  referral_code TEXT UNIQUE,
  referred_by UUID REFERENCES profiles(id),
  kyc_status TEXT DEFAULT 'pending' CHECK (kyc_status IN ('pending', 'verified', 'rejected')),
  is_verified BOOLEAN DEFAULT false,
  avatar_url TEXT,
  date_of_birth DATE,
  city TEXT,
  country TEXT DEFAULT 'Kenya',
  preferred_language TEXT DEFAULT 'en',
  last_login_ip INET,
  last_login_at TIMESTAMPTZ,
  device_info JSONB,
  is_active BOOLEAN DEFAULT true,
  is_banned BOOLEAN DEFAULT false,
  ban_reason TEXT,
  role TEXT DEFAULT 'user' CHECK (role IN ('user', 'admin', 'super_admin')),
  metadata JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. WALLETS TABLE
CREATE TABLE IF NOT EXISTS wallets (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID REFERENCES profiles(id) ON DELETE CASCADE UNIQUE NOT NULL,
  main_balance DECIMAL(10,2) DEFAULT 0 CHECK (main_balance >= 0),
  bonus_balance DECIMAL(10,2) DEFAULT 0 CHECK (bonus_balance >= 0),
  affiliate_balance DECIMAL(10,2) DEFAULT 0 CHECK (affiliate_balance >= 0),
  total_balance DECIMAL(10,2) GENERATED ALWAYS AS (main_balance + bonus_balance + affiliate_balance) STORED,
  lifetime_deposits DECIMAL(10,2) DEFAULT 0,
  lifetime_withdrawals DECIMAL(10,2) DEFAULT 0,
  lifetime_winnings DECIMAL(10,2) DEFAULT 0,
  lifetime_bets DECIMAL(10,2) DEFAULT 0,
  last_updated TIMESTAMPTZ DEFAULT NOW(),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. BETS TABLE
CREATE TABLE IF NOT EXISTS bets (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID REFERENCES profiles(id) ON DELETE CASCADE NOT NULL,
  selections JSONB NOT NULL,
  stake DECIMAL(10,2) NOT NULL CHECK (stake >= 10),
  total_odds DECIMAL(10,2) NOT NULL CHECK (total_odds >= 1),
  potential_winnings DECIMAL(10,2) NOT NULL,
  status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'won', 'lost', 'cancelled')),
  bet_type TEXT DEFAULT 'single' CHECK (bet_type IN ('single', 'accumulator', 'system')),
  system_type TEXT,
  is_cashout BOOLEAN DEFAULT false,
  cashout_amount DECIMAL(10,2),
  cashout_at TIMESTAMPTZ,
  result JSONB,
  settled_at TIMESTAMPTZ,
  reference_number TEXT UNIQUE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 4. TRANSACTIONS TABLE
CREATE TABLE IF NOT EXISTS transactions (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID REFERENCES profiles(id) ON DELETE CASCADE NOT NULL,
  type TEXT CHECK (type IN ('deposit', 'withdrawal', 'bet', 'win', 'bonus', 'referral', 'jackpot', 'cashout', 'adjustment')),
  amount DECIMAL(10,2) NOT NULL,
  balance_before DECIMAL(10,2),
  balance_after DECIMAL(10,2),
  status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'failed', 'cancelled')),
  description TEXT,
  reference TEXT UNIQUE,
  method TEXT CHECK (method IN ('mpesa', 'airtel', 'card', 'bank', 'bonus')),
  payment_type TEXT CHECK (payment_type IN ('stk', 'paybill', 'bank_transfer')),
  metadata JSONB,
  ip_address INET,
  user_agent TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 5. M-PESA TRANSACTIONS TABLE
CREATE TABLE IF NOT EXISTS mpesa_transactions (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID REFERENCES profiles(id) ON DELETE CASCADE NOT NULL,
  phone_number TEXT NOT NULL,
  amount DECIMAL(10,2) NOT NULL,
  reference TEXT UNIQUE,
  description TEXT,
  status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'failed')),
  type TEXT CHECK (type IN ('deposit', 'withdrawal')),
  payment_type TEXT CHECK (payment_type IN ('stk', 'paybill')),
  checkout_request_id TEXT UNIQUE,
  mpesa_receipt_number TEXT,
  transaction_date TEXT,
  result_code INTEGER,
  result_description TEXT,
  merchant_request_id TEXT,
  metadata JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 6. LEAGUES TABLE
CREATE TABLE IF NOT EXISTS leagues (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  country TEXT,
  logo TEXT,
  season TEXT,
  is_popular BOOLEAN DEFAULT false,
  metadata JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 7. MATCHES TABLE
CREATE TABLE IF NOT EXISTS matches (
  id INTEGER PRIMARY KEY,
  league_id INTEGER REFERENCES leagues(id) ON DELETE CASCADE,
  home_team TEXT NOT NULL,
  away_team TEXT NOT NULL,
  home_team_logo TEXT,
  away_team_logo TEXT,
  match_date TIMESTAMPTZ NOT NULL,
  status TEXT DEFAULT 'scheduled' CHECK (status IN ('scheduled', 'live', 'finished', 'cancelled', 'postponed')),
  home_score INTEGER DEFAULT 0,
  away_score INTEGER DEFAULT 0,
  elapsed_minutes INTEGER,
  odds JSONB,
  statistics JSONB,
  events JSONB,
  metadata JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 8. JACKPOT WEEKS TABLE
CREATE TABLE IF NOT EXISTS jackpot_weeks (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  week_number INTEGER NOT NULL,
  start_date TIMESTAMPTZ NOT NULL,
  end_date TIMESTAMPTZ NOT NULL,
  matches JSONB NOT NULL,
  total_pool DECIMAL(10,2) DEFAULT 0,
  total_entries INTEGER DEFAULT 0,
  status TEXT DEFAULT 'open' CHECK (status IN ('open', 'closed', 'settled')),
  prizes JSONB,
  metadata JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 9. JACKPOT ENTRIES TABLE
CREATE TABLE IF NOT EXISTS jackpot_entries (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID REFERENCES profiles(id) ON DELETE CASCADE NOT NULL,
  week_id UUID REFERENCES jackpot_weeks(id) ON DELETE CASCADE,
  week_number INTEGER NOT NULL,
  selections JSONB NOT NULL,
  stake DECIMAL(10,2) NOT NULL,
  total_odds DECIMAL(10,2) NOT NULL,
  potential_winnings DECIMAL(10,2) NOT NULL,
  status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'won', 'lost')),
  correct_predictions INTEGER,
  rank INTEGER,
  prize_amount DECIMAL(10,2),
  reference_number TEXT UNIQUE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 10. NOTIFICATIONS TABLE
CREATE TABLE IF NOT EXISTS notifications (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID REFERENCES profiles(id) ON DELETE CASCADE NOT NULL,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  type TEXT CHECK (type IN ('bet', 'win', 'deposit', 'withdrawal', 'bonus', 'promo', 'system')),
  data JSONB,
  is_read BOOLEAN DEFAULT false,
  read_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  expires_at TIMESTAMPTZ
);

-- 11. REFERRALS TABLE
CREATE TABLE IF NOT EXISTS referrals (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  referrer_id UUID REFERENCES profiles(id) ON DELETE CASCADE NOT NULL,
  referred_id UUID REFERENCES profiles(id) ON DELETE CASCADE UNIQUE NOT NULL,
  commission_earned DECIMAL(10,2) DEFAULT 0,
  status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'inactive')),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 12. AFFILIATE_COMMISSIONS TABLE
CREATE TABLE IF NOT EXISTS affiliate_commissions (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID REFERENCES profiles(id) ON DELETE CASCADE NOT NULL,
  referral_id UUID REFERENCES referrals(id) ON DELETE CASCADE,
  amount DECIMAL(10,2) NOT NULL,
  type TEXT CHECK (type IN ('deposit', 'bet', 'win')),
  rate DECIMAL(5,2) NOT NULL,
  status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'paid', 'cancelled')),
  paid_at TIMESTAMPTZ,
  metadata JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 13. SUPPORT TICKETS TABLE
CREATE TABLE IF NOT EXISTS support_tickets (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID REFERENCES profiles(id) ON DELETE CASCADE NOT NULL,
  ticket_number TEXT UNIQUE NOT NULL,
  subject TEXT NOT NULL,
  message TEXT NOT NULL,
  category TEXT CHECK (category IN ('deposit', 'withdrawal', 'betting', 'bonus', 'account', 'technical', 'other')),
  priority TEXT DEFAULT 'normal' CHECK (priority IN ('low', 'normal', 'high', 'urgent')),
  status TEXT DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'resolved', 'closed')),
  attachments JSONB,
  assigned_to UUID REFERENCES profiles(id),
  resolved_at TIMESTAMPTZ,
  metadata JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 14. TICKET_REPLIES TABLE
CREATE TABLE IF NOT EXISTS ticket_replies (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  ticket_id UUID REFERENCES support_tickets(id) ON DELETE CASCADE,
  user_id UUID REFERENCES profiles(id) ON DELETE CASCADE,
  message TEXT NOT NULL,
  is_staff BOOLEAN DEFAULT false,
  attachments JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 15. KYC_DOCUMENTS TABLE
CREATE TABLE IF NOT EXISTS kyc_documents (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID REFERENCES profiles(id) ON DELETE CASCADE NOT NULL,
  document_type TEXT CHECK (document_type IN ('id_card', 'passport', 'drivers_license', 'utility_bill')),
  document_number TEXT,
  front_image TEXT,
  back_image TEXT,
  status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'verified', 'rejected')),
  rejection_reason TEXT,
  verified_by UUID REFERENCES profiles(id),
  verified_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  metadata JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 16. BONUSES TABLE
CREATE TABLE IF NOT EXISTS bonuses (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  type TEXT CHECK (type IN ('welcome', 'deposit', 'cashback', 'freebet', 'referral', 'special')),
  amount DECIMAL(10,2) NOT NULL,
  percentage DECIMAL(5,2),
  min_deposit DECIMAL(10,2),
  max_amount DECIMAL(10,2),
  wagering_requirements DECIMAL(5,2),
  valid_from TIMESTAMPTZ,
  valid_to TIMESTAMPTZ,
  is_active BOOLEAN DEFAULT true,
  metadata JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 17. USER_BONUSES TABLE
CREATE TABLE IF NOT EXISTS user_bonuses (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID REFERENCES profiles(id) ON DELETE CASCADE NOT NULL,
  bonus_id UUID REFERENCES bonuses(id) ON DELETE CASCADE,
  amount DECIMAL(10,2) NOT NULL,
  wagered_amount DECIMAL(10,2) DEFAULT 0,
  wagering_requirement DECIMAL(10,2),
  status TEXT DEFAULT 'active' CHECK (status IN ('active', 'completed', 'expired', 'cancelled')),
  expires_at TIMESTAMPTZ,
  claimed_at TIMESTAMPTZ DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);

-- 18. SYSTEM_SETTINGS TABLE
CREATE TABLE IF NOT EXISTS system_settings (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  key TEXT UNIQUE NOT NULL,
  value JSONB,
  description TEXT,
  updated_by UUID REFERENCES profiles(id),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 19. LOGS TABLE
CREATE TABLE IF NOT EXISTS logs (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID REFERENCES profiles(id),
  action TEXT NOT NULL,
  entity_type TEXT,
  entity_id TEXT,
  old_data JSONB,
  new_data JSONB,
  ip_address INET,
  user_agent TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 20. SESSIONS TABLE
CREATE TABLE IF NOT EXISTS sessions (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID REFERENCES profiles(id) ON DELETE CASCADE NOT NULL,
  session_token TEXT UNIQUE NOT NULL,
  device_info JSONB,
  ip_address INET,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  last_activity TIMESTAMPTZ DEFAULT NOW()
);

\echo '✅ Tables created successfully!'
