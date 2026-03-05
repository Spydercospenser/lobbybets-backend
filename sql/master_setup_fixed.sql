-- =====================================================
-- LOBBYBETS KENYA - MASTER SETUP (FIXED)
-- =====================================================
\echo '========================================='
\echo 'Starting LobbyBets Kenya Database Setup'
\echo '========================================='

-- First enable extensions
\echo 'Enabling extensions...'
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "citext";

-- Then run all schema files with full paths
\echo 'Creating tables...'
\i '/home/qml/projects/house-hunt-app/LobbyBets-Kenya/lobbybets-backend/sql/01_schema.sql'

\echo 'Adding seed data...'
\i '/home/qml/projects/house-hunt-app/LobbyBets-Kenya/lobbybets-backend/sql/02_seed_data.sql'

\echo 'Creating indexes...'
\i '/home/qml/projects/house-hunt-app/LobbyBets-Kenya/lobbybets-backend/sql/03_indexes.sql'

\echo 'Creating functions and triggers...'
\i '/home/qml/projects/house-hunt-app/LobbyBets-Kenya/lobbybets-backend/sql/04_functions_triggers.sql'

\echo 'Creating views...'
\i '/home/qml/projects/house-hunt-app/LobbyBets-Kenya/lobbybets-backend/sql/05_views.sql'

\echo 'Setting up RLS policies...'
\i '/home/qml/projects/house-hunt-app/LobbyBets-Kenya/lobbybets-backend/sql/06_rls_policies.sql'

\echo '========================================='
\echo '✅ LobbyBets Kenya Database Setup Complete!'
\echo '========================================='
