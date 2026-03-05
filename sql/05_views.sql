-- =====================================================
-- LOBBYBETS KENYA - VIEWS
-- =====================================================
-- Run AFTER 04_functions_triggers.sql
-- =====================================================

\echo 'Creating views for common queries...'

-- User summary view
CREATE OR REPLACE VIEW user_summary AS
SELECT 
  p.id,
  p.full_name,
  p.phone,
  p.email,
  p.kyc_status,
  p.is_verified,
  p.created_at as registered_at,
  w.main_balance,
  w.bonus_balance,
  w.affiliate_balance,
  w.total_balance,
  w.lifetime_deposits,
  w.lifetime_withdrawals,
  w.lifetime_winnings,
  w.lifetime_bets,
  (SELECT COUNT(*) FROM bets WHERE user_id = p.id) as total_bets,
  (SELECT COUNT(*) FROM bets WHERE user_id = p.id AND status = 'won') as won_bets
FROM profiles p
LEFT JOIN wallets w ON p.id = w.user_id;

-- Live matches view
CREATE OR REPLACE VIEW live_matches AS
SELECT 
  m.*,
  l.name as league_name,
  l.country as league_country
FROM matches m
JOIN leagues l ON m.league_id = l.id
WHERE m.status = 'live'
ORDER BY m.match_date;

-- Upcoming matches view
CREATE OR REPLACE VIEW upcoming_matches AS
SELECT 
  m.*,
  l.name as league_name,
  l.country as league_country
FROM matches m
JOIN leagues l ON m.league_id = l.id
WHERE m.status = 'scheduled' AND m.match_date > NOW()
ORDER BY m.match_date;

\echo '✅ Views created successfully!'
