-- =====================================================
-- LOBBYBETS KENYA - MASTER SETUP
-- =====================================================
-- Run this file to set up everything
-- =====================================================

\echo '========================================='
\echo 'Starting LobbyBets Kenya Database Setup'
\echo '========================================='

\i '01_schema.sql'
\i '02_seed_data.sql'
\i '03_indexes.sql'
\i '04_functions_triggers.sql'
\i '05_views.sql'
\i '06_rls_policies.sql'

\echo '========================================='
\echo '✅ LobbyBets Kenya Database Setup Complete!'
\echo '========================================='
