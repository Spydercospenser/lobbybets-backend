-- =====================================================
-- LOBBYBETS KENYA - FUNCTIONS AND TRIGGERS
-- =====================================================
-- Run AFTER 03_indexes.sql
-- =====================================================

\echo 'Creating functions and triggers...'

-- Function to update updated_at column
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply update triggers
CREATE TRIGGER update_profiles_updated_at BEFORE UPDATE ON profiles
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_wallets_updated_at BEFORE UPDATE ON wallets
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_bets_updated_at BEFORE UPDATE ON bets
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to generate reference numbers
CREATE OR REPLACE FUNCTION generate_reference(prefix TEXT DEFAULT 'REF')
RETURNS TEXT AS $$
DECLARE
  ref TEXT;
  done BOOLEAN;
BEGIN
  done := false;
  WHILE NOT done LOOP
    ref := prefix || '-' || TO_CHAR(NOW(), 'YYMMDD') || '-' || 
           LPAD(FLOOR(RANDOM() * 1000000)::TEXT, 6, '0');
    done := NOT EXISTS (SELECT 1 FROM transactions WHERE reference = ref);
  END LOOP;
  RETURN ref;
END;
$$ LANGUAGE plpgsql;

-- Function to handle new user creation
CREATE OR REPLACE FUNCTION handle_new_user()
RETURNS TRIGGER AS $$
DECLARE
  ref_code TEXT;
BEGIN
  -- Generate unique referral code
  ref_code := UPPER(SUBSTRING(MD5(NEW.id::TEXT) FROM 1 FOR 8));
  
  -- Set referral code
  NEW.referral_code := ref_code;
  
  -- Create wallet with welcome bonus
  INSERT INTO wallets (user_id, main_balance, bonus_balance)
  VALUES (NEW.id, 100, 0);
  
  -- Create welcome bonus transaction
  INSERT INTO transactions (
    user_id, type, amount, status, description, reference,
    balance_before, balance_after
  ) VALUES (
    NEW.id, 'bonus', 100, 'completed', 'Welcome Bonus',
    'BONUS-' || NEW.id, 0, 100
  );
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for new users
DROP TRIGGER IF EXISTS on_profile_created ON profiles;
CREATE TRIGGER on_profile_created
  AFTER INSERT ON profiles
  FOR EACH ROW
  EXECUTE FUNCTION handle_new_user();

-- Function to handle bet placement
CREATE OR REPLACE FUNCTION handle_bet_placement()
RETURNS TRIGGER AS $$
DECLARE
  wallet_balance DECIMAL(10,2);
BEGIN
  -- Check wallet balance
  SELECT main_balance INTO wallet_balance
  FROM wallets WHERE user_id = NEW.user_id;
  
  IF wallet_balance < NEW.stake THEN
    RAISE EXCEPTION 'Insufficient balance';
  END IF;
  
  -- Deduct from wallet
  UPDATE wallets 
  SET main_balance = main_balance - NEW.stake,
      lifetime_bets = lifetime_bets + NEW.stake,
      last_updated = NOW()
  WHERE user_id = NEW.user_id;
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER on_bet_placed
  BEFORE INSERT ON bets
  FOR EACH ROW
  EXECUTE FUNCTION handle_bet_placement();

\echo '✅ Functions and triggers created successfully!'
