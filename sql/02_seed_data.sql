-- =====================================================
-- LOBBYBETS KENYA - SEED DATA
-- =====================================================
-- Run AFTER 01_schema.sql
-- =====================================================

\echo 'Inserting seed data...'

-- Insert popular leagues
INSERT INTO leagues (id, name, country, is_popular) VALUES
(39, 'Premier League', 'England', true),
(140, 'La Liga', 'Spain', true),
(78, 'Bundesliga', 'Germany', true),
(135, 'Serie A', 'Italy', true),
(61, 'Ligue 1', 'France', true),
(2, 'UEFA Champions League', 'Europe', true),
(3, 'UEFA Europa League', 'Europe', true);

-- Insert system settings
INSERT INTO system_settings (key, value, description) VALUES
('min_deposit', '{"amount": 10, "currency": "KES"}', 'Minimum deposit amount'),
('max_deposit', '{"amount": 70000, "currency": "KES"}', 'Maximum deposit amount per transaction'),
('min_withdrawal', '{"amount": 100, "currency": "KES"}', 'Minimum withdrawal amount'),
('max_withdrawal', '{"amount": 70000, "currency": "KES"}', 'Maximum withdrawal amount per transaction'),
('daily_withdrawal_limit', '{"amount": 140000, "currency": "KES"}', 'Daily withdrawal limit per user'),
('min_bet_stake', '{"amount": 10, "currency": "KES"}', 'Minimum bet stake'),
('welcome_bonus', '{"amount": 100, "currency": "KES"}', 'Welcome bonus amount'),
('referral_rate', '{"percentage": 10}', 'Referral commission rate'),
('support_email', '{"email": "support@lobbybets.co.ke"}', 'Support email'),
('support_phone', '{"phone": "+254700123456"}', 'Support phone');

-- Insert default bonuses
INSERT INTO bonuses (name, description, type, amount, percentage, min_deposit, max_amount, valid_from) VALUES
('Welcome Bonus', 'KES 100 welcome bonus for new users', 'welcome', 100, 0, 0, 100, NOW()),
('First Deposit Bonus', '100% match bonus up to KES 10,000', 'deposit', 0, 100, 100, 10000, NOW()),
('Referral Bonus', 'KES 200 for each friend who deposits', 'referral', 200, 0, 0, NULL, NOW());

-- Insert sample upcoming matches
INSERT INTO matches (id, league_id, home_team, away_team, match_date, status, odds) VALUES
(1001, 39, 'Manchester City', 'Arsenal', NOW() + INTERVAL '2 days', 'scheduled', 
 '{"home": 1.85, "draw": 3.40, "away": 4.50}'),
(1002, 39, 'Liverpool', 'Chelsea', NOW() + INTERVAL '2 days', 'scheduled',
 '{"home": 1.90, "draw": 3.30, "away": 4.20}'),
(1003, 140, 'Real Madrid', 'Barcelona', NOW() + INTERVAL '3 days', 'scheduled',
 '{"home": 2.10, "draw": 3.20, "away": 3.80}');

\echo '✅ Seed data inserted successfully!'
