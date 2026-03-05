-- =====================================================
-- LOBBYBETS KENYA - MASTER SETUP SCRIPT
-- =====================================================
-- Run this script to set up the entire database
-- Usage: psql -U postgres -d lobbybets -f 00_setup.sql
-- =====================================================

\echo 'Starting LobbyBets Kenya Database Setup...'

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "citext";

\echo 'Extensions enabled!'
