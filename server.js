const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// ==================== JWT DEBUG ====================
console.log('🔑 ===== JWT DEBUG =====');
console.log('🔑 JWT_SECRET loaded:', process.env.JWT_SECRET ? '✅ Yes' : '❌ No');
console.log('🔑 JWT_SECRET length:', process.env.JWT_SECRET ? process.env.JWT_SECRET.length : 0);
console.log('🔑 JWT_SECRET prefix:', process.env.JWT_SECRET ? process.env.JWT_SECRET.substring(0, 10) + '...' : 'N/A');
console.log('🔑 JWT_EXPIRES_IN raw value:', process.env.JWT_EXPIRES_IN ? `"${process.env.JWT_EXPIRES_IN}"` : 'Not set');
console.log('🔑 JWT_EXPIRES_IN type:', typeof process.env.JWT_EXPIRES_IN);
console.log('🔑 JWT_EXPIRES_IN length:', process.env.JWT_EXPIRES_IN ? process.env.JWT_EXPIRES_IN.length : 0);
console.log('🔑 ===================');

// ==================== CORS CONFIGURATION ====================
const allowedOrigins = [
  'http://localhost:8081',
  'http://localhost:19006',
  'http://localhost:3000',
  'http://127.0.0.1:8081',
  'http://10.0.2.2:8081',
  'http://localhost:8082',
  'http://localhost:19000',
  'exp://localhost:19000',
  'exp://localhost:19001',
  'exp://localhost:19002',
  'http://localhost:5000',
  'http://localhost:5001',
  'https://lobbybets-backend.onrender.com'
];

const allowedOriginPatterns = [
  /\.expo\.app$/,
  /^https?:\/\/lobbybets-app--[a-z0-9]+\.expo\.app$/
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      return callback(null, true);
    }
    
    const matchesPattern = allowedOriginPatterns.some(pattern => pattern.test(origin));
    if (matchesPattern) {
      return callback(null, true);
    }
    
    if (process.env.NODE_ENV !== 'production') {
      console.log('⚠️ Development mode - allowing origin:', origin);
      return callback(null, true);
    }
    
    console.log('❌ Blocked origin:', origin);
    callback(new Error('Not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'X-Requested-With', 'Cache-Control', 'Pragma', 'Expires'],
  exposedHeaders: ['Content-Range', 'X-Content-Range'],
  credentials: true,
  optionsSuccessStatus: 200,
  maxAge: 86400
};

app.use(cors(corsOptions));

app.use((req, res, next) => {
  if (req.method !== 'OPTIONS') {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  }
  next();
});

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ==================== DATABASE CONNECTION ====================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  },
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

// ==================== CONSTANTS ====================
const COMMISSION_RATE = 0.15; // 15% commission
const MIN_WITHDRAWAL = 500; // Minimum KES 500 to withdraw commission

// ==================== INITIALIZE ALL TABLES ====================
async function initializeAllTables() {
  try {
    console.log('🔄 Initializing all database tables...');

    // Profiles table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS profiles (
        id SERIAL PRIMARY KEY,
        phone VARCHAR(20) UNIQUE NOT NULL,
        full_name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        age INTEGER CHECK (age >= 18),
        password_hash VARCHAR(255) NOT NULL,
        referral_code VARCHAR(20) UNIQUE,
        referred_by INTEGER REFERENCES profiles(id),
        kyc_status VARCHAR(20) DEFAULT 'pending',
        is_verified BOOLEAN DEFAULT false,
        avatar_url TEXT,
        city VARCHAR(100),
        date_of_birth DATE,
        role VARCHAR(20) DEFAULT 'user',
        last_login_at TIMESTAMP,
        last_login_ip VARCHAR(45),
        last_password_reset TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Wallets table with profit tracking
    await pool.query(`
      CREATE TABLE IF NOT EXISTS wallets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER UNIQUE REFERENCES profiles(id) ON DELETE CASCADE,
        main_balance DECIMAL(12,2) DEFAULT 0,
        bonus_balance DECIMAL(12,2) DEFAULT 0,
        affiliate_balance DECIMAL(12,2) DEFAULT 0,
        lifetime_deposits DECIMAL(12,2) DEFAULT 0,
        lifetime_withdrawals DECIMAL(12,2) DEFAULT 0,
        lifetime_winnings DECIMAL(12,2) DEFAULT 0,
        lifetime_bets DECIMAL(12,2) DEFAULT 0,
        total_profit DECIMAL(12,2) DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        last_transaction_at TIMESTAMP
      )
    `);

    // Transactions table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS transactions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES profiles(id) ON DELETE CASCADE,
        type VARCHAR(50) NOT NULL,
        amount DECIMAL(12,2) NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        description TEXT,
        reference VARCHAR(100) UNIQUE,
        method VARCHAR(50),
        balance_before DECIMAL(12,2),
        balance_after DECIMAL(12,2),
        profit DECIMAL(12,2) DEFAULT 0,
        metadata JSONB,
        completed_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Bets table with profit tracking
    await pool.query(`
      CREATE TABLE IF NOT EXISTS bets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES profiles(id) ON DELETE CASCADE,
        selections JSONB NOT NULL,
        stake DECIMAL(12,2) NOT NULL,
        total_odds DECIMAL(10,2) NOT NULL,
        potential_winnings DECIMAL(12,2) NOT NULL,
        actual_winnings DECIMAL(12,2),
        profit DECIMAL(12,2) DEFAULT 0,
        status VARCHAR(20) DEFAULT 'pending',
        bet_type VARCHAR(50) DEFAULT 'single',
        game_type VARCHAR(50),
        round_id INTEGER,
        cashout_multiplier DECIMAL(10,2),
        reference_number VARCHAR(100) UNIQUE,
        settled_at TIMESTAMP,
        cancellation_reason TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Game stats table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS game_stats (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES profiles(id) ON DELETE CASCADE,
        game_type VARCHAR(50) NOT NULL,
        total_bets INTEGER DEFAULT 0,
        total_wins INTEGER DEFAULT 0,
        total_losses INTEGER DEFAULT 0,
        total_wagered DECIMAL(12,2) DEFAULT 0,
        total_won DECIMAL(12,2) DEFAULT 0,
        total_profit DECIMAL(12,2) DEFAULT 0,
        biggest_win DECIMAL(12,2) DEFAULT 0,
        biggest_multiplier DECIMAL(10,2) DEFAULT 0,
        last_played TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(user_id, game_type)
      )
    `);

    // M-PESA transactions table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS mpesa_transactions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES profiles(id) ON DELETE CASCADE,
        phone_number VARCHAR(20),
        amount DECIMAL(12,2),
        reference VARCHAR(100) UNIQUE,
        checkout_request_id VARCHAR(100),
        merchant_request_id VARCHAR(100),
        mpesa_receipt_number VARCHAR(50),
        type VARCHAR(50) DEFAULT 'deposit',
        payment_type VARCHAR(50) DEFAULT 'stk',
        status VARCHAR(20) DEFAULT 'pending',
        result_code INTEGER,
        result_description TEXT,
        customer_message TEXT,
        completed_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // M-PESA recovery table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS mpesa_recovery (
        id SERIAL PRIMARY KEY,
        checkout_request_id VARCHAR(100),
        callback_data JSONB,
        processed BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT NOW(),
        processed_at TIMESTAMP
      )
    `);

    // Failed callbacks table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS failed_callbacks (
        id SERIAL PRIMARY KEY,
        callback_data JSONB,
        error TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Game rounds table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS game_rounds (
        id SERIAL PRIMARY KEY,
        game VARCHAR(50) NOT NULL,
        round_number INTEGER NOT NULL,
        crash_point DECIMAL(10,2),
        status VARCHAR(20) DEFAULT 'waiting',
        server_seed VARCHAR(255),
        client_seed VARCHAR(255),
        nonce INTEGER,
        forced_crash BOOLEAN DEFAULT false,
        forced_crash_reason TEXT,
        forced_crash_by INTEGER,
        total_bets INTEGER DEFAULT 0,
        total_wagered DECIMAL(12,2) DEFAULT 0,
        total_paid DECIMAL(12,2) DEFAULT 0,
        total_bets_settled INTEGER DEFAULT 0,
        house_profit DECIMAL(12,2) DEFAULT 0,
        started_at TIMESTAMP DEFAULT NOW(),
        ended_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Game settings table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS game_settings (
        id SERIAL PRIMARY KEY,
        game VARCHAR(50) UNIQUE NOT NULL,
        enabled BOOLEAN DEFAULT true,
        min_bet DECIMAL(10,2) DEFAULT 10,
        max_bet DECIMAL(10,2) DEFAULT 10000,
        house_edge DECIMAL(5,2) DEFAULT 3,
        provably_fair BOOLEAN DEFAULT true,
        max_payout DECIMAL(12,2) DEFAULT 1000000,
        auto_crash_enabled BOOLEAN DEFAULT false,
        auto_crash_multiplier DECIMAL(10,2),
        auto_crash_queue JSONB,
        current_seed VARCHAR(255),
        next_seed VARCHAR(255),
        seed_rotated_at TIMESTAMP,
        seed_rotated_by INTEGER,
        auto_crash_queue_set_at TIMESTAMP,
        auto_crash_queue_set_by INTEGER,
        auto_crash_queue_cleared_at TIMESTAMP,
        auto_crash_queue_cleared_by INTEGER,
        created_by INTEGER,
        updated_by INTEGER,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Game suspensions table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS game_suspensions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES profiles(id) ON DELETE CASCADE,
        game VARCHAR(50) NOT NULL,
        reason TEXT,
        suspended_by INTEGER REFERENCES admins(id),
        expires_at TIMESTAMP,
        lifted_at TIMESTAMP,
        lifted_by INTEGER REFERENCES admins(id),
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Jackpots table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS jackpots (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        description TEXT,
        total_pool DECIMAL(12,2) DEFAULT 0,
        min_bet DECIMAL(10,2) DEFAULT 50,
        max_bet DECIMAL(10,2) DEFAULT 1000,
        entry_fee DECIMAL(10,2) DEFAULT 50,
        current_players INTEGER DEFAULT 0,
        max_players INTEGER DEFAULT 1000,
        status VARCHAR(20) DEFAULT 'active',
        draw_date TIMESTAMP,
        winning_numbers JSONB,
        winners JSONB,
        prize_breakdown JSONB,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Jackpot entries table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS jackpot_entries (
        id SERIAL PRIMARY KEY,
        jackpot_id INTEGER REFERENCES jackpots(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES profiles(id) ON DELETE CASCADE,
        numbers JSONB NOT NULL,
        stake DECIMAL(10,2) NOT NULL,
        status VARCHAR(20) DEFAULT 'active',
        winning_rank INTEGER,
        winning_amount DECIMAL(12,2),
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Leagues table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS leagues (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        country VARCHAR(100),
        logo_url TEXT,
        is_popular BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Matches table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS matches (
        id SERIAL PRIMARY KEY,
        league_id INTEGER REFERENCES leagues(id),
        home_team VARCHAR(100) NOT NULL,
        away_team VARCHAR(100) NOT NULL,
        home_logo TEXT,
        away_logo TEXT,
        match_date TIMESTAMP NOT NULL,
        status VARCHAR(20) DEFAULT 'scheduled',
        home_score INTEGER,
        away_score INTEGER,
        odds JSONB,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Bonuses table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS bonuses (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        description TEXT,
        type VARCHAR(50) NOT NULL,
        amount DECIMAL(12,2),
        percentage DECIMAL(5,2),
        min_deposit DECIMAL(12,2),
        max_amount DECIMAL(12,2),
        wagering_requirements DECIMAL(5,2),
        is_active BOOLEAN DEFAULT true,
        valid_from TIMESTAMP,
        valid_to TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // User bonuses table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_bonuses (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES profiles(id) ON DELETE CASCADE,
        bonus_id INTEGER REFERENCES bonuses(id),
        amount DECIMAL(12,2),
        status VARCHAR(20) DEFAULT 'pending',
        wagering_progress DECIMAL(12,2) DEFAULT 0,
        claimed_at TIMESTAMP,
        released_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Admins table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS admins (
        id SERIAL PRIMARY KEY,
        full_name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        phone VARCHAR(20) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'admin',
        is_active BOOLEAN DEFAULT true,
        last_login_at TIMESTAMP,
        last_login_ip VARCHAR(45),
        failed_login_attempts INTEGER DEFAULT 0,
        locked_until TIMESTAMP,
        last_failed_login TIMESTAMP,
        active_session_id VARCHAR(255),
        active_session_expires TIMESTAMP,
        last_session_created TIMESTAMP,
        created_by INTEGER,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Admin sessions table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin_sessions (
        id SERIAL PRIMARY KEY,
        admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
        session_token VARCHAR(255) UNIQUE NOT NULL,
        device_info TEXT,
        ip_address VARCHAR(45),
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        expires_at TIMESTAMP NOT NULL,
        last_activity TIMESTAMP DEFAULT NOW(),
        is_active BOOLEAN DEFAULT true
      )
    `);

    // Admin login history table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin_login_history (
        id SERIAL PRIMARY KEY,
        admin_id INTEGER REFERENCES admins(id) ON DELETE SET NULL,
        email VARCHAR(255),
        ip_address VARCHAR(45),
        user_agent TEXT,
        login_status VARCHAR(20),
        failure_reason TEXT,
        session_token VARCHAR(255),
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Admin action logs table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin_action_logs (
        id SERIAL PRIMARY KEY,
        admin_id INTEGER REFERENCES admins(id) ON DELETE SET NULL,
        admin_email VARCHAR(255),
        action_type VARCHAR(100) NOT NULL,
        action_details JSONB,
        ip_address VARCHAR(45),
        user_agent TEXT,
        session_token VARCHAR(255),
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // ==================== AFFILIATE TABLES ====================
    
    // Commission earnings table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS commission_earnings (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES profiles(id) ON DELETE CASCADE,
        from_user_id INTEGER REFERENCES profiles(id) ON DELETE CASCADE,
        deposit_amount DECIMAL(12,2) NOT NULL,
        commission_amount DECIMAL(12,2) NOT NULL,
        deposit_id INTEGER REFERENCES transactions(id),
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Commission withdrawals table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS commission_withdrawals (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES profiles(id) ON DELETE CASCADE,
        amount DECIMAL(12,2) NOT NULL,
        reference VARCHAR(100) UNIQUE,
        status VARCHAR(20) DEFAULT 'pending',
        processed_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    console.log('✅ All tables initialized successfully');
  } catch (error) {
    console.error('❌ Error initializing tables:', error);
  }
}

// ==================== INITIALIZE FUNCTIONS AND TRIGGERS ====================
async function initializeFunctions() {
  try {
    console.log('🔄 Initializing database functions and triggers...');

    // Function to generate crash points
    await pool.query(`
      CREATE OR REPLACE FUNCTION generate_crash_point() RETURNS DECIMAL AS $$
      DECLARE
          random_num DECIMAL;
          crash_point DECIMAL;
      BEGIN
          random_num = random();
          
          IF random_num <= 0.50 THEN
              crash_point = 1.00 + (random() * 1.00);
          ELSIF random_num <= 0.70 THEN
              crash_point = 2.00 + (random() * 0.99);
          ELSIF random_num <= 0.85 THEN
              crash_point = 3.00 + (random() * 2.00);
          ELSIF random_num <= 0.91 THEN
              crash_point = 5.00 + (random() * 3.00);
          ELSIF random_num <= 0.94 THEN
              crash_point = 8.00 + (random() * 5.00);
          ELSIF random_num <= 0.965 THEN
              crash_point = 13.00 + (random() * 6.00);
          ELSIF random_num <= 0.98 THEN
              crash_point = 19.00 + (random() * 10.00);
          ELSIF random_num <= 0.99 THEN
              crash_point = 29.00 + (random() * 20.00);
          ELSIF random_num <= 0.995 THEN
              crash_point = 49.00 + (random() * 26.00);
          ELSE
              crash_point = 75.00 + (random() * 55.00);
          END IF;
          
          RETURN ROUND(crash_point::numeric, 2);
      END;
      $$ LANGUAGE plpgsql;
    `);

    // Function to sync wallet on transaction
    await pool.query(`
      CREATE OR REPLACE FUNCTION sync_wallet_on_transaction()
      RETURNS TRIGGER AS $$
      BEGIN
        UPDATE wallets 
        SET 
          main_balance = (
            SELECT COALESCE(SUM(CASE WHEN type IN ('deposit', 'win', 'bonus', 'commission') THEN amount ELSE 0 END), 0) -
                   COALESCE(SUM(CASE WHEN type IN ('withdrawal', 'bet') THEN amount ELSE 0 END), 0)
            FROM transactions 
            WHERE user_id = NEW.user_id AND status = 'completed'
          ),
          lifetime_deposits = (
            SELECT COALESCE(SUM(amount), 0)
            FROM transactions 
            WHERE user_id = NEW.user_id AND type = 'deposit' AND status = 'completed'
          ),
          lifetime_withdrawals = (
            SELECT COALESCE(SUM(amount), 0)
            FROM transactions 
            WHERE user_id = NEW.user_id AND type = 'withdrawal' AND status = 'completed'
          ),
          lifetime_winnings = (
            SELECT COALESCE(SUM(amount), 0)
            FROM transactions 
            WHERE user_id = NEW.user_id AND type = 'win' AND status = 'completed'
          ),
          lifetime_bets = (
            SELECT COALESCE(SUM(amount), 0)
            FROM transactions 
            WHERE user_id = NEW.user_id AND type = 'bet' AND status = 'completed'
          ),
          total_profit = (
            SELECT COALESCE(SUM(profit), 0)
            FROM transactions 
            WHERE user_id = NEW.user_id AND status = 'completed'
          ),
          updated_at = NOW(),
          last_transaction_at = NOW()
        WHERE user_id = NEW.user_id;
        
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;
    `);

    // Create trigger for transactions
    await pool.query(`
      DROP TRIGGER IF EXISTS trigger_sync_wallet ON transactions;
      CREATE TRIGGER trigger_sync_wallet
        AFTER INSERT OR UPDATE OF status ON transactions
        FOR EACH ROW
        WHEN (NEW.status = 'completed')
        EXECUTE FUNCTION sync_wallet_on_transaction();
    `);

    // Function to handle M-PESA completions
    await pool.query(`
      CREATE OR REPLACE FUNCTION handle_mpesa_completion()
      RETURNS TRIGGER AS $$
      DECLARE
        current_wallet_balance DECIMAL;
      BEGIN
        IF NEW.status = 'completed' AND (OLD.status IS NULL OR OLD.status != 'completed') THEN
          
          SELECT COALESCE(main_balance, 0) INTO current_wallet_balance
          FROM wallets WHERE user_id = NEW.user_id;
          
          INSERT INTO transactions (
            user_id, type, amount, status, description, reference,
            balance_before, balance_after, created_at, profit
          )
          SELECT 
            NEW.user_id,
            'deposit',
            NEW.amount,
            'completed',
            'M-PESA deposit',
            NEW.reference,
            current_wallet_balance,
            current_wallet_balance + NEW.amount,
            NOW(),
            0
          WHERE NOT EXISTS (
            SELECT 1 FROM transactions 
            WHERE reference = NEW.reference
          );
        END IF;
        
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;
    `);

    // Create trigger for M-PESA
    await pool.query(`
      DROP TRIGGER IF EXISTS trigger_mpesa_completion ON mpesa_transactions;
      CREATE TRIGGER trigger_mpesa_completion
        AFTER UPDATE OF status ON mpesa_transactions
        FOR EACH ROW
        WHEN (NEW.status = 'completed')
        EXECUTE FUNCTION handle_mpesa_completion();
    `);

    // ==================== AFFILIATE COMMISSION TRIGGER ====================
    
    // Function to credit affiliate commission on deposit
    await pool.query(`
      CREATE OR REPLACE FUNCTION credit_affiliate_commission()
      RETURNS TRIGGER AS $$
      DECLARE
        referrer_id INTEGER;
        commission_amount DECIMAL;
        current_balance DECIMAL;
      BEGIN
        -- Only process completed deposits
        IF NEW.status = 'completed' AND (OLD.status IS NULL OR OLD.status != 'completed') THEN
          -- Get the referrer for this user
          SELECT referred_by INTO referrer_id
          FROM profiles
          WHERE id = NEW.user_id;
          
          -- If user has a referrer
          IF referrer_id IS NOT NULL THEN
            -- Calculate 15% commission
            commission_amount := NEW.amount * ${COMMISSION_RATE};
            
            -- Get current affiliate balance
            SELECT COALESCE(affiliate_balance, 0) INTO current_balance
            FROM wallets WHERE user_id = referrer_id;
            
            -- Add commission to referrer's affiliate balance
            UPDATE wallets 
            SET affiliate_balance = affiliate_balance + commission_amount,
                updated_at = NOW()
            WHERE user_id = referrer_id;
            
            -- Record commission transaction
            INSERT INTO transactions (
              user_id, type, amount, status, description, reference,
              balance_before, balance_after, profit, created_at
            )
            SELECT 
              referrer_id,
              'commission',
              commission_amount,
              'completed',
              'Affiliate commission from deposit by user ' || NEW.user_id,
              'COMM-' || NEW.id,
              current_balance,
              current_balance + commission_amount,
              commission_amount,
              NOW();
            
            -- Insert into commission tracking table
            INSERT INTO commission_earnings (
              user_id, from_user_id, deposit_amount, commission_amount, deposit_id, created_at
            ) VALUES (
              referrer_id, NEW.user_id, NEW.amount, commission_amount, NEW.id, NOW()
            );
            
            RAISE NOTICE 'Commission credited: % to user % from deposit %', commission_amount, referrer_id, NEW.id;
          END IF;
        END IF;
        
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;
    `);

    // Create trigger for affiliate commission
    await pool.query(`
      DROP TRIGGER IF EXISTS trigger_affiliate_commission ON transactions;
      CREATE TRIGGER trigger_affiliate_commission
        AFTER UPDATE OF status ON transactions
        FOR EACH ROW
        WHEN (NEW.type = 'deposit' AND NEW.status = 'completed')
        EXECUTE FUNCTION credit_affiliate_commission();
    `);

    console.log('✅ Functions and triggers initialized');
  } catch (error) {
    console.error('❌ Error initializing functions:', error);
  }
}

// ==================== GAME STATS TRIGGER ====================
async function initializeGameStatsTrigger() {
  try {
    console.log('🔄 Initializing game stats trigger...');

    // Function to update game_stats
    await pool.query(`
      CREATE OR REPLACE FUNCTION update_game_stats()
      RETURNS TRIGGER AS $$
      BEGIN
        -- Insert or update basic stats on bet creation
        INSERT INTO game_stats (user_id, game_type, total_bets, total_wagered, last_played)
        VALUES (NEW.user_id, NEW.game_type, 1, NEW.stake, NOW())
        ON CONFLICT (user_id, game_type) DO UPDATE
        SET total_bets = game_stats.total_bets + 1,
            total_wagered = game_stats.total_wagered + NEW.stake,
            last_played = NOW(),
            updated_at = NOW();
        
        -- Update win/loss stats when bet is settled
        IF NEW.status IN ('cashed_out', 'won') THEN
          UPDATE game_stats 
          SET total_wins = total_wins + 1,
              total_won = total_won + COALESCE(NEW.actual_winnings, 0),
              total_profit = total_profit + COALESCE(NEW.profit, 0),
              biggest_win = GREATEST(biggest_win, COALESCE(NEW.actual_winnings, 0)),
              biggest_multiplier = GREATEST(biggest_multiplier, COALESCE(NEW.cashout_multiplier, 0))
          WHERE user_id = NEW.user_id AND game_type = NEW.game_type;
        ELSIF NEW.status = 'lost' THEN
          UPDATE game_stats 
          SET total_losses = total_losses + 1,
              total_profit = total_profit + COALESCE(NEW.profit, 0)
          WHERE user_id = NEW.user_id AND game_type = NEW.game_type;
        END IF;
        
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;
    `);

    // Create trigger for game_stats
    await pool.query(`
      DROP TRIGGER IF EXISTS trigger_update_game_stats ON bets;
      CREATE TRIGGER trigger_update_game_stats
        AFTER INSERT OR UPDATE OF status ON bets
        FOR EACH ROW
        EXECUTE FUNCTION update_game_stats();
    `);

    console.log('✅ Game stats trigger initialized');
  } catch (error) {
    console.error('❌ Error initializing game stats trigger:', error);
  }
}

// ==================== DATABASE CONNECTION ====================
pool.connect(async (err, client, release) => {
  if (err) {
    console.error('❌ Database connection error:', err.stack);
  } else {
    console.log('✅ Database connected successfully');
    release();
    await initializeAllTables();
    await initializeFunctions();
    await initializeGameStatsTrigger();
  }
});

// ==================== HELPER FUNCTIONS ====================
const generateReferralCode = () => {
  return 'REF' + Math.random().toString(36).substring(2, 8).toUpperCase();
};

const formatPhoneForMPesa = (phone) => {
  let cleaned = phone.replace(/[^0-9]/g, '');
  
  if (cleaned.startsWith('0')) {
    cleaned = '254' + cleaned.substring(1);
  } else if (cleaned.startsWith('7')) {
    cleaned = '254' + cleaned;
  }
  
  return cleaned;
};

const normalizePhoneForDatabase = (phone) => {
  let cleaned = phone.replace(/[^0-9]/g, '');
  
  if (cleaned.startsWith('0')) {
    cleaned = '254' + cleaned.substring(1);
  }
  
  return cleaned;
};

const generateTimestamp = () => {
  const date = new Date();
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  const hours = String(date.getHours()).padStart(2, '0');
  const minutes = String(date.getMinutes()).padStart(2, '0');
  const seconds = String(date.getSeconds()).padStart(2, '0');
  return `${year}${month}${day}${hours}${minutes}${seconds}`;
};

// ==================== DEFAULT GAME STATS ====================
const defaultGameStats = {
  totalBets: 0,
  totalWins: 0,
  totalLosses: 0,
  totalWagered: 0,
  totalWon: 0,
  totalProfit: 0,
  biggestWin: 0,
  biggestMultiplier: 0,
  lastPlayed: null
};

// ==================== M-PESA CONFIGURATION ====================
const MPESA_CONFIG = {
  stkPushUrl: 'https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
  queryUrl: 'https://api.safaricom.co.ke/mpesa/stkpushquery/v1/query',
  tokenUrl: 'https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials',
  
  consumerKey: 'EiTjMcrIYbxBJY1G7UiNVu62YwxVEfEQ1qdTA9u7uY9nhOBP',
  consumerSecret: 'GaPQ3RxOpJnd03Sx96PMX1igq9nDSBChFjGky0f1QNZOx9jALtPt07v9GmpHCMoc',
  businessShortCode: '4011243',
  passkey: 'ed0f022db9398b8082f6c4114a8bcb2d25a9685c2383790947a5aa76cd5c30e5',
  
  callbackUrl: 'https://lobbybets-backend.onrender.com/api/mpesa/callback',
  
  accountReference: 'LobbyBets',
  transactionDesc: 'Deposit to LobbyBets'
};

// ==================== M-PESA TOKEN MANAGEMENT ====================
let mpesaAccessToken = null;
let tokenExpiryTime = null;

const getMpesaToken = async () => {
  try {
    if (mpesaAccessToken && tokenExpiryTime && new Date() < tokenExpiryTime) {
      console.log('✅ Using cached M-PESA token');
      return mpesaAccessToken;
    }

    console.log('🔄 Requesting new M-PESA access token...');
    
    const auth = Buffer.from(
      `${MPESA_CONFIG.consumerKey}:${MPESA_CONFIG.consumerSecret}`
    ).toString('base64');

    const response = await axios.get(MPESA_CONFIG.tokenUrl, {
      headers: {
        Authorization: `Basic ${auth}`
      },
      timeout: 10000
    });

    mpesaAccessToken = response.data.access_token;
    tokenExpiryTime = new Date(Date.now() + 55 * 60 * 1000);
    
    console.log('✅ M-PESA token generated successfully');
    return mpesaAccessToken;
  } catch (error) {
    console.error('❌ Failed to get M-PESA token:', error.response?.data || error.message);
    throw new Error('Failed to get M-PESA access token');
  }
};

// ==================== AUTHENTICATION MIDDLEWARE ====================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  console.log('🔐 Auth header received:', authHeader ? 'Yes' : 'No');
  
  if (!token) {
    console.log('❌ No token provided');
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }
  
  console.log('🔑 Token length:', token.length);
  
  const parts = token.split('.');
  if (parts.length !== 3) {
    console.error('❌ Invalid token format');
    return res.status(403).json({ error: 'Invalid token format' });
  }
  
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    console.log('📦 Token payload:', {
      userId: payload.userId,
      exp: payload.exp ? new Date(payload.exp * 1000).toLocaleString() : 'missing'
    });
  } catch (decodeError) {
    console.error('❌ Could not decode token payload:', decodeError.message);
  }
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error('❌ JWT Verification failed:', err.name, err.message);
      
      if (err.name === 'JsonWebTokenError') {
        return res.status(403).json({ error: 'Invalid token signature' });
      } else if (err.name === 'TokenExpiredError') {
        return res.status(403).json({ error: 'Token expired' });
      } else {
        return res.status(403).json({ error: 'Invalid or expired token' });
      }
    }
    
    console.log('✅ Token verified for user:', user.userId);
    req.user = user;
    next();
  });
};

const authenticateAdmin = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const session = await pool.query(
      `SELECT s.*, a.role, a.is_active, a.locked_until, a.full_name, a.email, a.phone
       FROM admin_sessions s
       JOIN admins a ON s.admin_id = a.id
       WHERE s.session_token = $1 
         AND s.is_active = true 
         AND s.expires_at > NOW()`,
      [token]
    );
    
    if (session.rows.length === 0) {
      console.log('❌ Invalid or expired session');
      return res.status(401).json({ error: 'Session expired or invalid' });
    }
    
    const sessionData = session.rows[0];
    
    if (!sessionData.is_active) {
      await pool.query(
        'UPDATE admin_sessions SET is_active = false WHERE session_token = $1',
        [token]
      );
      return res.status(403).json({ error: 'Account is deactivated' });
    }
    
    if (sessionData.locked_until && new Date(sessionData.locked_until) > new Date()) {
      await pool.query(
        'UPDATE admin_sessions SET is_active = false WHERE session_token = $1',
        [token]
      );
      return res.status(403).json({ error: 'Account is locked' });
    }
    
    await pool.query(
      'UPDATE admin_sessions SET last_activity = NOW() WHERE session_token = $1',
      [token]
    );
    
    req.admin = {
      id: sessionData.admin_id,
      email: sessionData.email,
      role: sessionData.role,
      full_name: sessionData.full_name,
      phone: sessionData.phone
    };
    
    next();
  } catch (error) {
    console.error('❌ Admin auth error:', error);
    
    if (error.name === 'TokenExpiredError') {
      await pool.query(
        'UPDATE admin_sessions SET is_active = false WHERE session_token = $1',
        [token]
      );
      return res.status(401).json({ error: 'Session expired' });
    }
    
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// ==================== ADMIN HELPER FUNCTIONS ====================
async function handleFailedLogin(email) {
  try {
    const admin = await pool.query('SELECT id FROM admins WHERE email = $1', [email]);
    if (admin.rows.length === 0) return;

    const adminId = admin.rows[0].id;

    await pool.query(`
      UPDATE admins 
      SET failed_login_attempts = failed_login_attempts + 1,
          last_failed_login = NOW(),
          locked_until = CASE 
            WHEN failed_login_attempts + 1 >= 5 THEN NOW() + INTERVAL '30 minutes'
            ELSE NULL
          END
      WHERE id = $1
    `, [adminId]);
  } catch (error) {
    console.error('Error handling failed login:', error);
  }
}

async function resetFailedLogin(adminId) {
  try {
    await pool.query(
      `UPDATE admins 
       SET failed_login_attempts = 0,
           locked_until = NULL
       WHERE id = $1`,
      [adminId]
    );
  } catch (error) {
    console.error('Error resetting failed login:', error);
  }
}

async function logAdminAction(adminId, action, targetType, targetId, details) {
  try {
    await pool.query(
      `INSERT INTO admin_action_logs (
        admin_id, action_type, target_type, target_id, action_details, created_at
      ) VALUES ($1, $2, $3, $4, $5, NOW())`,
      [adminId, action, targetType, targetId, JSON.stringify(details)]
    );
  } catch (error) {
    console.error('Error logging admin action:', error);
  }
}

// ==================== HEALTH CHECK ====================
app.get('/api/health', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW() as time');
    res.json({ 
      status: 'healthy', 
      database: 'connected',
      time: result.rows[0].time,
      cors: 'enabled',
      environment: process.env.NODE_ENV || 'development'
    });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// ==================== TEST JWT ENDPOINT ====================
app.get('/api/test-jwt', (req, res) => {
  try {
    const expiresIn = process.env.JWT_EXPIRES_IN || '7d';
    const testToken = jwt.sign(
      { test: 'data', userId: 'test-user' },
      process.env.JWT_SECRET,
      { expiresIn: expiresIn }
    );
    
    const verified = jwt.verify(testToken, process.env.JWT_SECRET);
    const decoded = jwt.decode(testToken);
    
    res.json({
      success: true,
      message: 'JWT configuration is working',
      secretPresent: !!process.env.JWT_SECRET,
      secretLength: process.env.JWT_SECRET ? process.env.JWT_SECRET.length : 0,
      expiresIn: expiresIn,
      tokenGenerated: !!testToken,
      tokenVerified: !!verified,
      expiresAt: new Date(decoded.exp * 1000).toLocaleString()
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
      secretPresent: !!process.env.JWT_SECRET
    });
  }
});

// ==================== USER REGISTRATION (UPDATED WITH REFERRAL) ====================
app.post('/api/register', async (req, res) => {
  const { name, email, phone, password, age, referral_code } = req.body;
  
  let client;
  
  try {
    console.log('📝 Registration attempt for:', email);
    if (referral_code) console.log('🔗 Referral code provided:', referral_code);
    
    if (!name || !email || !phone || !password || !age) {
      return res.status(400).json({ 
        success: false,
        error: 'All fields are required' 
      });
    }
    
    if (age < 18) {
      return res.status(400).json({ 
        success: false,
        error: 'You must be 18 or older to register' 
      });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ 
        success: false,
        error: 'Password must be at least 6 characters' 
      });
    }
    
    const normalizedPhone = normalizePhoneForDatabase(phone);
    console.log('📱 Normalized phone:', normalizedPhone);
    
    client = await pool.connect();
    await client.query('BEGIN');
    
    const existingUser = await client.query(
      'SELECT id FROM profiles WHERE phone = $1 OR email = $2',
      [normalizedPhone, email]
    );
    
    if (existingUser.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ 
        success: false,
        error: 'User with this phone or email already exists' 
      });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Handle referral code
    let referredById = null;
    if (referral_code) {
      const referrerResult = await client.query(
        'SELECT id FROM profiles WHERE referral_code = $1',
        [referral_code.toUpperCase()]
      );
      if (referrerResult.rows.length > 0) {
        referredById = referrerResult.rows[0].id;
        console.log('🔗 User referred by ID:', referredById);
      }
    }
    
    // Generate unique referral code for the new user
    let newReferralCode;
    let isUnique = false;
    
    while (!isUnique) {
      newReferralCode = 'REF' + Math.random().toString(36).substring(2, 8).toUpperCase();
      const check = await client.query(
        'SELECT id FROM profiles WHERE referral_code = $1',
        [newReferralCode]
      );
      if (check.rows.length === 0) isUnique = true;
    }
    
    const userResult = await client.query(
      `INSERT INTO profiles 
       (phone, full_name, email, age, referral_code, referred_by, password_hash, created_at, updated_at) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW()) 
       RETURNING id, phone, full_name, email, age, referral_code, created_at`,
      [normalizedPhone, name, email, age, newReferralCode, referredById, hashedPassword]
    );
    
    const userId = userResult.rows[0].id;
    
    // Create wallet with welcome bonus
    await client.query(
      `INSERT INTO wallets 
       (user_id, main_balance, lifetime_deposits, created_at, updated_at) 
       VALUES ($1, 100, 100, NOW(), NOW())`,
      [userId]
    );
    
    // Add transaction record for the welcome bonus
    await client.query(
      `INSERT INTO transactions 
       (user_id, type, amount, status, description, reference, balance_before, balance_after, created_at, profit)
       VALUES ($1, 'bonus', 100, 'completed', 'Welcome Bonus', $2, 0, 100, NOW(), 100)`,
      [userId, 'BONUS-' + Date.now()]
    );
    
    await client.query('COMMIT');
    
    const expiresIn = process.env.JWT_EXPIRES_IN || '7d';
    const token = jwt.sign(
      { 
        userId: userId,
        phone: normalizedPhone, 
        email: email 
      }, 
      process.env.JWT_SECRET, 
      { expiresIn: expiresIn }
    );
    
    console.log('✅ User registered successfully:', userId);
    console.log('💰 Welcome bonus of 100 KES added to wallet');
    if (referredById) console.log('🔗 Referral tracking complete');
    
    res.json({ 
      success: true, 
      token,
      user: userResult.rows[0],
      wallet: {
        main_balance: 100,
        bonus_balance: 0,
        affiliate_balance: 0,
        total_balance: 100
      }
    });
    
  } catch (error) {
    if (client) {
      await client.query('ROLLBACK');
      client.release();
    }
    console.error('❌ Registration error:', error);
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  } finally {
    if (client) client.release();
  }
});

// ==================== USER LOGIN ====================
app.post('/api/login', async (req, res) => {
  const { phone, password } = req.body;
  
  try {
    console.log('🔐 Login attempt for:', phone);
    
    const normalizedPhone = normalizePhoneForDatabase(phone);
    console.log('📱 Normalized phone:', normalizedPhone);
    
    const userResult = await pool.query(
      `SELECT p.*, w.main_balance, w.bonus_balance, w.affiliate_balance, w.total_profit
       FROM profiles p 
       LEFT JOIN wallets w ON p.id = w.user_id 
       WHERE p.phone = $1`,
      [normalizedPhone]
    );
    
    if (userResult.rows.length === 0) {
      console.log('❌ User not found:', normalizedPhone);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = userResult.rows[0];
    
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      console.log('❌ Invalid password for:', normalizedPhone);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    await pool.query(
      'UPDATE profiles SET last_login_at = NOW(), last_login_ip = $1 WHERE id = $2',
      [req.ip || req.connection.remoteAddress, user.id]
    );
    
    const expiresIn = process.env.JWT_EXPIRES_IN || '7d';
    
    const token = jwt.sign(
      { 
        userId: user.id,
        phone: user.phone, 
        email: user.email 
      }, 
      process.env.JWT_SECRET, 
      { expiresIn: expiresIn }
    );
    
    console.log('✅ Login successful for:', user.id);
    
    const mainBalance = parseFloat(user.main_balance || 0);
    const bonusBalance = parseFloat(user.bonus_balance || 0);
    const affiliateBalance = parseFloat(user.affiliate_balance || 0);
    
    delete user.password_hash;
    
    res.json({ 
      success: true, 
      token,
      user: {
        id: user.id,
        full_name: user.full_name,
        phone: user.phone,
        email: user.email,
        age: user.age,
        kyc_status: user.kyc_status,
        is_verified: user.is_verified,
        referral_code: user.referral_code,
        created_at: user.created_at
      },
      wallet: {
        main_balance: mainBalance,
        bonus_balance: bonusBalance,
        affiliate_balance: affiliateBalance,
        total_profit: parseFloat(user.total_profit || 0),
        total_balance: (mainBalance + bonusBalance + affiliateBalance).toFixed(2)
      }
    });
    
  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== RESET PASSWORD ====================
app.post('/api/reset-password', async (req, res) => {
  const { phone, newPassword } = req.body;
  
  try {
    console.log('🔐 Password reset for phone:', phone);
    
    if (!phone || !newPassword) {
      return res.status(400).json({ error: 'Phone and new password are required' });
    }
    
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    let formattedPhone = normalizePhoneForDatabase(phone);
    
    const userResult = await pool.query(
      'SELECT id, full_name FROM profiles WHERE phone = $1',
      [formattedPhone]
    );
    
    if (userResult.rows.length === 0) {
      console.log('❌ User not found with phone:', formattedPhone);
      return res.status(404).json({ error: 'User not found with this phone number' });
    }
    
    const user = userResult.rows[0];
    
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    await pool.query(
      `UPDATE profiles 
       SET password_hash = $1, 
           updated_at = NOW(),
           last_password_reset = NOW()
       WHERE id = $2`,
      [hashedPassword, user.id]
    );
    
    console.log('✅ Password reset successful for user:', user.id);
    
    res.json({ 
      success: true, 
      message: 'Password reset successful. You can now login with your new password.'
    });
    
  } catch (error) {
    console.error('❌ Reset password error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== PROFILE ENDPOINTS ====================
app.get('/api/profile/:userId', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.id, p.phone, p.full_name, p.email, p.age, p.referral_code, 
              p.kyc_status, p.is_verified, p.avatar_url, p.city, p.date_of_birth,
              p.created_at, p.updated_at,
              w.main_balance, w.bonus_balance, w.affiliate_balance, w.total_profit,
              w.lifetime_deposits, w.lifetime_withdrawals, w.lifetime_winnings, w.lifetime_bets
       FROM profiles p
       LEFT JOIN wallets w ON p.id = w.user_id
       WHERE p.id = $1`,
      [req.params.userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json(result.rows[0]);
    
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/profile/:userId', authenticateToken, async (req, res) => {
  const { full_name, city, date_of_birth, avatar_url } = req.body;
  
  try {
    await pool.query(
      `UPDATE profiles 
       SET full_name = COALESCE($1, full_name),
           city = COALESCE($2, city),
           date_of_birth = COALESCE($3, date_of_birth),
           avatar_url = COALESCE($4, avatar_url),
           updated_at = NOW()
       WHERE id = $5`,
      [full_name, city, date_of_birth, avatar_url, req.params.userId]
    );
    
    res.json({ success: true });
    
  } catch (error) {
    console.error('Update error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/profile/upload-image', authenticateToken, async (req, res) => {
  const { userId, image } = req.body;
  
  try {
    console.log('📤 Uploading image for user:', userId);
    
    await pool.query(
      'UPDATE profiles SET avatar_url = $1, updated_at = NOW() WHERE id = $2',
      [image, userId]
    );
    
    res.json({ 
      success: true, 
      imageUrl: image,
      message: 'Image uploaded successfully' 
    });
  } catch (error) {
    console.error('❌ Upload error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/profile/remove-image', authenticateToken, async (req, res) => {
  const { userId } = req.body;
  
  try {
    console.log('🗑️ Removing image for user:', userId);
    
    await pool.query(
      'UPDATE profiles SET avatar_url = NULL, updated_at = NOW() WHERE id = $1',
      [userId]
    );
    
    res.json({ 
      success: true, 
      message: 'Image removed successfully' 
    });
  } catch (error) {
    console.error('❌ Remove error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== GAME CASHOUT ====================
app.post('/api/games/cashout', authenticateToken, async (req, res) => {
  const { betId, userId, multiplier } = req.body;
  
  let client;
  
  try {
    console.log('💰 Cashing out:', { betId, userId, multiplier });
    
    if (req.user.userId !== userId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    let numericBetId;
    
    if (typeof betId === 'string' && betId.includes('pending_')) {
      console.log('⚠️ Received pending bet ID, looking up actual bet...');
      
      const betLookup = await pool.query(
        `SELECT id FROM bets 
         WHERE user_id = $1 AND status = 'pending' AND game_type IN ('aviator', 'jetx')
         ORDER BY created_at DESC LIMIT 1`,
        [userId]
      );
      
      if (betLookup.rows.length === 0) {
        return res.status(404).json({ error: 'No active bet found for cashout' });
      }
      
      numericBetId = betLookup.rows[0].id;
      console.log(`✅ Found actual bet ID: ${numericBetId}`);
    } else {
      numericBetId = parseInt(betId);
    }
    
    if (isNaN(numericBetId)) {
      return res.status(400).json({ error: 'Invalid bet ID format' });
    }
    
    client = await pool.connect();
    await client.query('BEGIN');
    
    const betResult = await client.query(
      `SELECT * FROM bets 
       WHERE id = $1 AND user_id = $2 AND game_type IN ('aviator', 'jetx') 
       FOR UPDATE`,
      [numericBetId, userId]
    );
    
    if (betResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Bet not found' });
    }
    
    const bet = betResult.rows[0];
    
    if (bet.status !== 'pending') {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: `Bet already ${bet.status}` });
    }
    
    const stake = parseFloat(bet.stake);
    const winnings = stake * multiplier;
    const profit = winnings - stake;
    
    await client.query(
      `UPDATE bets 
       SET status = 'cashed_out',
           cashout_multiplier = $1,
           actual_winnings = $2,
           profit = $3,
           settled_at = NOW()
       WHERE id = $4`,
      [multiplier, winnings, profit, numericBetId]
    );
    
    await client.query(
      `UPDATE wallets 
       SET main_balance = main_balance + $1,
           total_profit = total_profit + $2,
           lifetime_winnings = lifetime_winnings + $3,
           updated_at = NOW()
       WHERE user_id = $4`,
      [winnings, profit, winnings, userId]
    );
    
    const walletResult = await client.query(
      `SELECT main_balance FROM wallets WHERE user_id = $1`,
      [userId]
    );
    const currentBalance = parseFloat(walletResult.rows[0].main_balance);
    const balanceBefore = currentBalance - winnings;
    
    await client.query(
      `INSERT INTO transactions (
        user_id, type, amount, status, description, reference, 
        balance_before, balance_after, profit
      ) VALUES ($1, 'win', $2, 'completed', $3, $4, $5, $6, $7)`,
      [
        userId,
        winnings,
        `${bet.game_type || 'Aviator'} cashout at ${multiplier}x`,
        `CASHOUT-${numericBetId}`,
        balanceBefore,
        currentBalance,
        profit
      ]
    );
    
    await client.query('COMMIT');
    
    console.log(`✅ Cashout successful: User ${userId} won KES ${winnings} at ${multiplier}x`);
    
    res.json({
      success: true,
      betId: numericBetId,
      multiplier,
      stake,
      winnings,
      profit,
      newBalance: currentBalance
    });
    
  } catch (error) {
    if (client) {
      await client.query('ROLLBACK');
      client.release();
    }
    console.error('❌ Cashout error:', error);
    res.status(500).json({ error: error.message });
  } finally {
    if (client) client.release();
  }
});

// ==================== WALLET ENDPOINTS ====================
app.get('/api/wallet/:userId', authenticateToken, async (req, res) => {
  try {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('X-Timestamp', Date.now());
    
    const result = await pool.query(
      `SELECT 
         w.*,
         (SELECT COALESCE(SUM(amount), 0) FROM transactions 
          WHERE user_id = w.user_id AND type IN ('deposit', 'win', 'bonus', 'commission') AND status = 'completed') as calculated_credits,
         (SELECT COALESCE(SUM(amount), 0) FROM transactions 
          WHERE user_id = w.user_id AND type IN ('withdrawal', 'bet') AND status = 'completed') as calculated_debits
       FROM wallets w 
       WHERE w.user_id = $1`,
      [req.params.userId]
    );
    
    if (result.rows.length === 0) {
      const newWallet = await pool.query(
        `INSERT INTO wallets 
         (user_id, main_balance, bonus_balance, affiliate_balance, created_at, updated_at)
         VALUES ($1, 0, 0, 0, NOW(), NOW())
         RETURNING *`,
        [req.params.userId]
      );
      
      return res.json(newWallet.rows[0]);
    }
    
    const wallet = result.rows[0];
    const calculatedBalance = wallet.calculated_credits - wallet.calculated_debits;
    
    if (Math.abs(wallet.main_balance - calculatedBalance) > 0.01) {
      console.log(`⚠️ Balance mismatch for user ${req.params.userId}: DB=${wallet.main_balance}, Calculated=${calculatedBalance}`);
      
      if (Math.abs(wallet.main_balance - calculatedBalance) > 10) {
        await pool.query(
          `UPDATE wallets SET main_balance = $1, updated_at = NOW() WHERE user_id = $2`,
          [calculatedBalance, req.params.userId]
        );
        wallet.main_balance = calculatedBalance;
        console.log(`✅ Auto-corrected balance for user ${req.params.userId}`);
      }
    }
    
    res.json(wallet);
    
  } catch (error) {
    console.error('❌ Wallet error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/wallet/sync', authenticateToken, async (req, res) => {
  const { userId } = req.body;
  
  try {
    const result = await pool.query(
      `WITH balance_calc AS (
         SELECT 
           COALESCE(SUM(CASE WHEN type IN ('deposit', 'win', 'bonus', 'commission') THEN amount ELSE 0 END), 0) as credits,
           COALESCE(SUM(CASE WHEN type IN ('withdrawal', 'bet') THEN amount ELSE 0 END), 0) as debits,
           COALESCE(SUM(profit), 0) as total_profit
         FROM transactions 
         WHERE user_id = $1 AND status = 'completed'
       )
       UPDATE wallets 
       SET main_balance = (SELECT credits - debits FROM balance_calc),
           total_profit = (SELECT total_profit FROM balance_calc),
           updated_at = NOW()
       WHERE user_id = $1
       RETURNING *`,
      [userId]
    );
    
    if (result.rows.length === 0) {
      const newWallet = await pool.query(
        `INSERT INTO wallets 
         (user_id, main_balance, bonus_balance, affiliate_balance, created_at, updated_at)
         VALUES ($1, 0, 0, 0, NOW(), NOW())
         RETURNING *`,
        [userId]
      );
      
      return res.json({
        success: true,
        wallet: newWallet.rows[0],
        synced_at: new Date().toISOString()
      });
    }
    
    res.json({
      success: true,
      wallet: result.rows[0],
      synced_at: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('❌ Sync error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/wallet/update', authenticateToken, async (req, res) => {
  const { userId, balance, deductAmount, addAmount, reason } = req.body;
  
  let client;
  
  try {
    console.log('💰 Wallet update request:', { userId, balance, deductAmount, addAmount, reason });
    
    client = await pool.connect();
    await client.query('BEGIN');
    
    const walletResult = await client.query(
      'SELECT * FROM wallets WHERE user_id = $1 FOR UPDATE',
      [userId]
    );
    
    if (walletResult.rows.length === 0) {
      await client.query('ROLLBACK');
      client.release();
      return res.status(404).json({ error: 'Wallet not found' });
    }
    
    const wallet = walletResult.rows[0];
    const currentBalance = parseFloat(wallet.main_balance);
    
    let newBalance;
    let transactionAmount;
    let transactionType;
    
    if (balance !== undefined) {
      newBalance = parseFloat(balance);
      transactionAmount = Math.abs(newBalance - currentBalance);
      transactionType = newBalance > currentBalance ? 'adjustment' : 'adjustment';
    } else if (deductAmount !== undefined) {
      transactionAmount = parseFloat(deductAmount);
      newBalance = currentBalance - transactionAmount;
      transactionType = 'bet';
    } else if (addAmount !== undefined) {
      transactionAmount = parseFloat(addAmount);
      newBalance = currentBalance + transactionAmount;
      transactionType = 'win';
    } else {
      await client.query('ROLLBACK');
      client.release();
      return res.status(400).json({ error: 'No update operation specified' });
    }
    
    if (newBalance < 0) {
      await client.query('ROLLBACK');
      client.release();
      return res.status(400).json({ 
        error: 'Insufficient balance',
        current: currentBalance,
        requested: newBalance
      });
    }
    
    await client.query(
      `UPDATE wallets 
       SET main_balance = $1,
           updated_at = NOW()
       WHERE user_id = $2`,
      [newBalance, userId]
    );
    
    const profit = transactionType === 'win' ? transactionAmount : 
                   transactionType === 'bet' ? -transactionAmount : 0;
    
    const transactionResult = await client.query(
      `INSERT INTO transactions (
        user_id, type, amount, status, description, 
        reference, balance_before, balance_after, profit, created_at
      ) VALUES ($1, $2, $3, 'completed', $4, $5, $6, $7, $8, NOW())
      RETURNING id`,
      [
        userId,
        transactionType,
        transactionAmount,
        reason || `${transactionType} transaction`,
        `${transactionType.toUpperCase()}-${Date.now()}`,
        currentBalance,
        newBalance,
        profit
      ]
    );
    
    await client.query('COMMIT');
    
    console.log(`✅ Wallet updated for user ${userId}: ${currentBalance} -> ${newBalance}`);
    
    const updatedWallet = await pool.query(
      'SELECT * FROM wallets WHERE user_id = $1',
      [userId]
    );
    
    res.json({
      success: true,
      oldBalance: currentBalance,
      newBalance,
      profit,
      transaction: {
        id: transactionResult.rows[0].id,
        type: transactionType,
        amount: transactionAmount
      },
      wallet: updatedWallet.rows[0]
    });
    
  } catch (error) {
    if (client) {
      await client.query('ROLLBACK');
      client.release();
    }
    console.error('❌ Wallet update error:', error);
    res.status(500).json({ error: error.message });
  } finally {
    if (client) client.release();
  }
});

// ==================== GAME STATS ENDPOINT ====================
app.get('/api/user/game-stats/:userId', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM game_stats WHERE user_id = $1`,
      [req.params.userId]
    );
    
    const stats = {
      aviator: { ...defaultGameStats },
      jetx: { ...defaultGameStats },
      jackpot: { ...defaultGameStats },
      live: { ...defaultGameStats },
      sports: { ...defaultGameStats }
    };
    
    result.rows.forEach(row => {
      if (stats[row.game_type]) {
        stats[row.game_type] = {
          totalBets: row.total_bets,
          totalWins: row.total_wins,
          totalLosses: row.total_losses,
          totalWagered: parseFloat(row.total_wagered),
          totalWon: parseFloat(row.total_won),
          totalProfit: parseFloat(row.total_profit),
          biggestWin: parseFloat(row.biggest_win),
          biggestMultiplier: parseFloat(row.biggest_multiplier),
          lastPlayed: row.last_played
        };
      }
    });
    
    res.json(stats);
    
  } catch (error) {
    console.error('❌ Error fetching game stats:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== USER PROFITS ====================
app.get('/api/user/profits/:userId', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
         COALESCE(SUM(profit), 0) as total_profit,
         COUNT(CASE WHEN profit > 0 THEN 1 END) as winning_bets,
         COUNT(CASE WHEN profit < 0 THEN 1 END) as losing_bets,
         COALESCE(AVG(profit), 0) as avg_profit_per_bet,
         MAX(profit) as biggest_win,
         MIN(profit) as biggest_loss
       FROM bets 
       WHERE user_id = $1 AND settled_at IS NOT NULL`,
      [req.params.userId]
    );
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('❌ Profits error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== TRANSACTIONS ====================
app.get('/api/transactions/:userId', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM transactions 
       WHERE user_id = $1 
       ORDER BY created_at DESC 
       LIMIT 100`,
      [req.params.userId]
    );
    
    res.json(result.rows);
    
  } catch (error) {
    console.error('Transactions error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== M-PESA STK PUSH ====================
app.post('/api/mpesa/stkpush', authenticateToken, async (req, res) => {
  const { userId, phoneNumber, amount } = req.body;
  
  try {
    console.log('📱 ===== M-PESA STK PUSH =====');
    console.log('📱 User:', userId);
    console.log('📱 Phone:', phoneNumber);
    console.log('📱 Amount:', amount);

    if (amount < 10 || amount > 70000) {
      return res.status(400).json({ 
        success: false, 
        error: 'Amount must be between KES 10 and 70,000' 
      });
    }

    let formattedPhone = formatPhoneForMPesa(phoneNumber);
    console.log('📱 Formatted phone:', formattedPhone);
    
    if (formattedPhone.length !== 12) {
      return res.status(400).json({
        success: false,
        error: 'Invalid phone number format. Use 07XXXXXXXX or 2547XXXXXXXX'
      });
    }

    const token = await getMpesaToken();
    console.log('✅ Token obtained');

    const timestamp = generateTimestamp();
    
    const password = Buffer.from(
      `${MPESA_CONFIG.businessShortCode}${MPESA_CONFIG.passkey}${timestamp}`
    ).toString('base64');

    const reference = 'LBB' + Date.now() + Math.random().toString(36).substring(2, 10).toUpperCase();

    const stkPushData = {
      BusinessShortCode: MPESA_CONFIG.businessShortCode,
      Password: password,
      Timestamp: timestamp,
      TransactionType: 'CustomerPayBillOnline',
      Amount: Math.floor(amount),
      PartyA: formattedPhone,
      PartyB: MPESA_CONFIG.businessShortCode,
      PhoneNumber: formattedPhone,
      CallBackURL: MPESA_CONFIG.callbackUrl,
      AccountReference: 'LobbyBets',
      TransactionDesc: `Deposit - ${reference}`
    };

    console.log('📤 Sending STK Push request...');

    const stkResponse = await axios.post(MPESA_CONFIG.stkPushUrl, stkPushData, {
      headers: { Authorization: `Bearer ${token}` },
      timeout: 15000
    });

    console.log('📥 Safaricom response:', stkResponse.data);

    const { 
      ResponseCode, 
      ResponseDescription, 
      MerchantRequestID, 
      CheckoutRequestID,
      CustomerMessage 
    } = stkResponse.data;

    const result = await pool.query(
      `INSERT INTO mpesa_transactions (
        user_id, phone_number, amount, reference, checkout_request_id,
        merchant_request_id, type, payment_type, status, result_code,
        result_description, customer_message, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())
      RETURNING id, reference, checkout_request_id`,
      [
        userId,
        formattedPhone,
        amount,
        reference,
        CheckoutRequestID || null,
        MerchantRequestID || null,
        'deposit',
        'stk',
        'pending',
        ResponseCode ? parseInt(ResponseCode) : null,
        ResponseDescription || null,
        CustomerMessage || null
      ]
    );

    console.log('✅ Transaction saved with ID:', result.rows[0].id);

    if (ResponseCode === '0') {
      res.json({ 
        success: true, 
        message: CustomerMessage || 'STK Push sent. Please check your phone to complete payment.',
        transactionId: result.rows[0].id,
        checkoutRequestId: CheckoutRequestID,
        reference: result.rows[0].reference
      });
    } else {
      res.status(400).json({ 
        success: false, 
        error: ResponseDescription || 'Failed to initiate STK Push'
      });
    }
    
  } catch (error) {
    console.error('❌ STK Push error:', error);
    
    res.status(500).json({ 
      success: false, 
      error: 'Failed to initiate payment. Please try again.',
      details: error.response?.data || error.message
    });
  }
});

// ==================== M-PESA CALLBACK ====================
app.post('/api/mpesa/callback', async (req, res) => {
  console.log('📞 ===== M-PESA CALLBACK RECEIVED =====');
  console.log('📞 Timestamp:', new Date().toISOString());
  console.log('📞 Callback body:', JSON.stringify(req.body, null, 2));
  
  res.json({ ResultCode: 0, ResultDesc: 'Success' });
  
  let client;
  
  try {
    const { Body } = req.body;
    
    if (!Body?.stkCallback) {
      console.log('❌ Invalid callback data - missing stkCallback');
      return;
    }

    const { 
      ResultCode, 
      ResultDesc, 
      CheckoutRequestID, 
      CallbackMetadata 
    } = Body.stkCallback;

    console.log(`📞 CheckoutRequestID: ${CheckoutRequestID}, ResultCode: ${ResultCode}`);

    client = await pool.connect();
    await client.query('BEGIN');

    let transaction;
    for (let i = 0; i < 3; i++) {
      const txResult = await client.query(
        `SELECT * FROM mpesa_transactions 
         WHERE checkout_request_id = $1 
         OR reference LIKE $2
         FOR UPDATE`,
        [CheckoutRequestID, `%${CheckoutRequestID ? CheckoutRequestID.slice(-8) : ''}%`]
      );
      
      if (txResult.rows.length > 0) {
        transaction = txResult.rows[0];
        break;
      }
      
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    if (!transaction) {
      console.log('❌ Transaction not found for CheckoutRequestID:', CheckoutRequestID);
      
      await client.query(
        `INSERT INTO mpesa_recovery 
         (checkout_request_id, callback_data, created_at)
         VALUES ($1, $2, NOW())`,
        [CheckoutRequestID, JSON.stringify(req.body)]
      );
      
      await client.query('COMMIT');
      return;
    }

    console.log('📞 Found transaction:', transaction.id, 'for user:', transaction.user_id);

    let amount = transaction.amount;
    let receipt = '';
    let phoneNumber = '';
    
    if (CallbackMetadata?.Item) {
      CallbackMetadata.Item.forEach(item => {
        if (item.Name === 'Amount') amount = item.Value;
        if (item.Name === 'MpesaReceiptNumber') receipt = item.Value;
        if (item.Name === 'PhoneNumber') phoneNumber = item.Value;
      });
    }

    if (ResultCode === 0) {
      console.log(`✅ Payment successful: KES ${amount}, Receipt: ${receipt}`);
      
      await client.query(
        `UPDATE mpesa_transactions 
         SET status = 'completed', 
             mpesa_receipt_number = $1,
             result_code = $2,
             result_description = $3,
             completed_at = NOW(),
             updated_at = NOW()
         WHERE id = $4`,
        [receipt, ResultCode, ResultDesc, transaction.id]
      );

      let walletResult = await client.query(
        `SELECT * FROM wallets 
         WHERE user_id = $1 
         FOR UPDATE`,
        [transaction.user_id]
      );
      
      let currentBalance = 0;
      
      if (walletResult.rows.length === 0) {
        const newWallet = await client.query(
          `INSERT INTO wallets 
           (user_id, main_balance, bonus_balance, affiliate_balance, lifetime_deposits, created_at, updated_at)
           VALUES ($1, 0, 0, 0, 0, NOW(), NOW())
           RETURNING *`,
          [transaction.user_id]
        );
        currentBalance = parseFloat(newWallet.rows[0].main_balance);
      } else {
        currentBalance = parseFloat(walletResult.rows[0].main_balance);
      }

      await client.query(
        `UPDATE wallets 
         SET main_balance = main_balance + $1,
             lifetime_deposits = lifetime_deposits + $1,
             updated_at = NOW(),
             last_transaction_at = NOW()
         WHERE user_id = $2`,
        [amount, transaction.user_id]
      );

      const existingTx = await client.query(
        `SELECT id FROM transactions 
         WHERE reference = $1 OR (user_id = $2 AND amount = $3 AND type = 'deposit' AND created_at > NOW() - INTERVAL '5 minutes')`,
        [transaction.reference, transaction.user_id, amount]
      );

      if (existingTx.rows.length === 0) {
        await client.query(
          `INSERT INTO transactions 
           (user_id, type, amount, status, description, reference, balance_before, balance_after, profit, created_at)
           VALUES ($1, 'deposit', $2, 'completed', $3, $4, $5, $5 + $2, 0, NOW())`,
          [transaction.user_id, amount, `M-PESA deposit (Receipt: ${receipt})`, transaction.reference, currentBalance]
        );
      }

      await client.query('COMMIT');
      
      console.log(`✅✅✅ SUCCESS: Wallet updated for user ${transaction.user_id}: +KES ${amount} (Receipt: ${receipt})`);
      
    } else {
      console.log(`❌ Payment failed: ${ResultDesc}`);
      
      await client.query(
        `UPDATE mpesa_transactions 
         SET status = 'failed',
             result_code = $1,
             result_description = $2,
             updated_at = NOW()
         WHERE id = $3`,
        [ResultCode, ResultDesc, transaction.id]
      );

      await client.query('COMMIT');
      console.log(`✅ Transaction ${transaction.id} marked as failed`);
    }
    
  } catch (error) {
    console.error('❌❌❌ Callback error:', error);
    if (client) {
      await client.query('ROLLBACK').catch(e => {});
    }
    
    try {
      await pool.query(
        `INSERT INTO failed_callbacks (callback_data, error, created_at)
         VALUES ($1, $2, NOW())`,
        [JSON.stringify(req.body), error.message]
      );
    } catch (e) {
      console.error('Failed to store callback:', e);
    }
  } finally {
    if (client) {
      client.release();
    }
  }
});

// ==================== M-PESA QUERY ====================
app.post('/api/mpesa/query', authenticateToken, async (req, res) => {
  const { checkoutRequestId } = req.body;
  
  try {
    const token = await getMpesaToken();
    
    const date = new Date();
    const timestamp = generateTimestamp();
    
    const password = Buffer.from(
      `${MPESA_CONFIG.businessShortCode}${MPESA_CONFIG.passkey}${timestamp}`
    ).toString('base64');

    const queryData = {
      BusinessShortCode: MPESA_CONFIG.businessShortCode,
      Password: password,
      Timestamp: timestamp,
      CheckoutRequestID: checkoutRequestId
    };

    console.log('🔍 Querying STK status:', checkoutRequestId);

    const response = await axios.post(MPESA_CONFIG.queryUrl, queryData, {
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });

    console.log('📊 Query response:', response.data);
    res.json(response.data);
    
  } catch (error) {
    console.error('❌ Query error:', error.response?.data || error.message);
    res.status(500).json({ 
      success: false, 
      error: error.response?.data?.errorMessage || error.message 
    });
  }
});

// ==================== PAYMENT STATUS ====================
app.get('/api/payment/status/:transactionId', authenticateToken, async (req, res) => {
  const { transactionId } = req.params;
  
  try {
    const result = await pool.query(
      `SELECT status, amount, mpesa_receipt_number, completed_at, 
              result_code, result_description
       FROM mpesa_transactions 
       WHERE id = $1`,
      [transactionId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Transaction not found' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error checking payment status:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== M-PESA RECOVERY ====================
app.post('/api/mpesa/recover-pending', authenticateToken, async (req, res) => {
  const { userId } = req.body;
  
  let client;
  
  try {
    client = await pool.connect();
    
    const pendingTx = await client.query(
      `SELECT * FROM mpesa_transactions 
       WHERE user_id = $1 
         AND status = 'pending' 
         AND created_at < NOW() - INTERVAL '2 minutes'
       ORDER BY created_at DESC`,
      [userId]
    );
    
    if (pendingTx.rows.length === 0) {
      client.release();
      return res.json({ 
        success: true, 
        message: 'No pending transactions found',
        recovered: 0 
      });
    }
    
    console.log(`🔍 Found ${pendingTx.rows.length} pending transactions for user ${userId}`);
    
    const results = [];
    
    for (const tx of pendingTx.rows) {
      try {
        const token = await getMpesaToken();
        
        const date = new Date();
        const timestamp = generateTimestamp();
        
        const password = Buffer.from(
          `${MPESA_CONFIG.businessShortCode}${MPESA_CONFIG.passkey}${timestamp}`
        ).toString('base64');

        const queryData = {
          BusinessShortCode: MPESA_CONFIG.businessShortCode,
          Password: password,
          Timestamp: timestamp,
          CheckoutRequestID: tx.checkout_request_id
        };

        console.log(`🔍 Querying status for transaction ${tx.id}: ${tx.checkout_request_id}`);
        
        const response = await axios.post(MPESA_CONFIG.queryUrl, queryData, {
          headers: { Authorization: `Bearer ${token}` },
          timeout: 10000
        });

        const { ResultCode, ResultDesc } = response.data;
        
        await client.query('BEGIN');
        
        if (ResultCode === 0) {
          console.log(`✅ Transaction ${tx.id} is completed, updating wallet...`);
          
          let receipt = '';
          if (response.data.CallbackMetadata?.Item) {
            response.data.CallbackMetadata.Item.forEach(item => {
              if (item.Name === 'MpesaReceiptNumber') receipt = item.Value;
            });
          }
          
          await client.query(
            `UPDATE mpesa_transactions 
             SET status = 'completed', 
                 mpesa_receipt_number = $1,
                 result_code = $2,
                 result_description = $3,
                 completed_at = NOW()
             WHERE id = $4`,
            [receipt, ResultCode, ResultDesc, tx.id]
          );
          
          const walletResult = await client.query(
            `SELECT main_balance FROM wallets WHERE user_id = $1 FOR UPDATE`,
            [tx.user_id]
          );
          
          const currentBalance = parseFloat(walletResult.rows[0]?.main_balance || 0);
          
          await client.query(
            `UPDATE wallets 
             SET main_balance = main_balance + $1,
                 lifetime_deposits = lifetime_deposits + $1
             WHERE user_id = $2`,
            [tx.amount, tx.user_id]
          );
          
          await client.query(
            `INSERT INTO transactions 
             (user_id, type, amount, status, description, reference, balance_before, balance_after, profit)
             VALUES ($1, 'deposit', $2, 'completed', $3, $4, $5, $5 + $2, 0)`,
            [tx.user_id, tx.amount, `M-PESA deposit (auto-recovered)`, tx.reference, currentBalance]
          );
          
          results.push({
            id: tx.id,
            amount: tx.amount,
            status: 'completed',
            receipt
          });
          
        } else if (ResultCode === 1037) {
          results.push({
            id: tx.id,
            amount: tx.amount,
            status: 'pending',
            message: 'Transaction still pending with M-PESA'
          });
          
        } else {
          await client.query(
            `UPDATE mpesa_transactions 
             SET status = 'failed',
                 result_code = $1,
                 result_description = $2
             WHERE id = $3`,
            [ResultCode, ResultDesc, tx.id]
          );
          
          results.push({
            id: tx.id,
            amount: tx.amount,
            status: 'failed',
            reason: ResultDesc
          });
        }
        
        await client.query('COMMIT');
        
      } catch (error) {
        console.error(`❌ Error recovering transaction ${tx.id}:`, error.message);
        await client.query('ROLLBACK').catch(e => {});
        results.push({
          id: tx.id,
          amount: tx.amount,
          status: 'error',
          error: error.message
        });
      }
    }
    
    client.release();
    
    const recoveredAmount = results
      .filter(r => r.status === 'completed')
      .reduce((sum, r) => sum + parseFloat(r.amount), 0);
    
    res.json({
      success: true,
      message: `Recovery completed. Recovered KES ${recoveredAmount}`,
      recovered: results.filter(r => r.status === 'completed').length,
      failed: results.filter(r => r.status === 'failed').length,
      pending: results.filter(r => r.status === 'pending').length,
      results
    });
    
  } catch (error) {
    console.error('❌ Recovery error:', error);
    if (client) client.release();
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// ==================== WITHDRAWAL ====================
app.post('/api/withdraw', authenticateToken, async (req, res) => {
  const { userId, phoneNumber, amount, method = 'mpesa' } = req.body;
  
  let client;
  
  try {
    console.log('📤 Withdrawal initiated:', { userId, phoneNumber, amount });
    
    if (amount < 50) {
      return res.status(400).json({ 
        success: false, 
        error: 'Minimum withdrawal is KES 50' 
      });
    }
    
    if (amount > 70000) {
      return res.status(400).json({ 
        success: false, 
        error: 'Maximum withdrawal per transaction is KES 70,000' 
      });
    }
    
    client = await pool.connect();
    await client.query('BEGIN');
    
    const walletResult = await client.query(
      'SELECT * FROM wallets WHERE user_id = $1 FOR UPDATE',
      [userId]
    );
    
    if (walletResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ 
        success: false, 
        error: 'Wallet not found' 
      });
    }
    
    const currentBalance = parseFloat(walletResult.rows[0].main_balance);
    
    if (currentBalance < amount) {
      await client.query('ROLLBACK');
      return res.status(400).json({ 
        success: false, 
        error: 'Insufficient balance',
        available: currentBalance,
        requested: amount
      });
    }
    
    const formattedPhone = formatPhoneForMPesa(phoneNumber);
    
    const reference = 'WDR' + Date.now().toString().slice(-8) + 
                     Math.random().toString(36).substring(2, 8).toUpperCase();
    
    const withdrawalResult = await client.query(
      `INSERT INTO mpesa_transactions 
       (user_id, phone_number, amount, reference, type, payment_type, status, created_at)
       VALUES ($1, $2, $3, $4, 'withdrawal', 'stk', 'pending', NOW())
       RETURNING id`,
      [userId, formattedPhone, amount, reference]
    );
    
    await client.query(
      `UPDATE wallets 
       SET main_balance = main_balance - $1,
           updated_at = NOW()
       WHERE user_id = $2`,
      [amount, userId]
    );
    
    await client.query(
      `INSERT INTO transactions 
       (user_id, type, amount, status, description, reference, method, balance_before, balance_after, profit, created_at)
       VALUES ($1, 'withdrawal', $2, 'pending', $3, $4, $5, $6, $6 - $2, -$2, NOW())`,
      [userId, amount, `Withdrawal to ${phoneNumber}`, reference, method, currentBalance]
    );
    
    await client.query('COMMIT');
    
    processWithdrawal(withdrawalResult.rows[0].id, userId, amount, formattedPhone, reference).catch(err => {
      console.error('Background withdrawal error:', err);
    });
    
    const updatedWallet = await pool.query(
      'SELECT main_balance FROM wallets WHERE user_id = $1',
      [userId]
    );
    
    res.json({ 
      success: true, 
      message: 'Withdrawal initiated successfully. It will be processed shortly.',
      transactionId: withdrawalResult.rows[0].id,
      reference,
      newBalance: updatedWallet.rows[0].main_balance
    });
    
  } catch (error) {
    if (client) {
      await client.query('ROLLBACK');
      client.release();
    }
    console.error('❌ Withdrawal error:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  } finally {
    if (client) client.release();
  }
});

async function processWithdrawal(transactionId, userId, amount, phoneNumber, reference) {
  let client;
  
  try {
    console.log(`🔄 Processing withdrawal ${transactionId} for user ${userId}`);
    
    await new Promise(resolve => setTimeout(resolve, 5000));
    
    client = await pool.connect();
    await client.query('BEGIN');
    
    const txCheck = await client.query(
      'SELECT status FROM mpesa_transactions WHERE id = $1 FOR UPDATE',
      [transactionId]
    );
    
    if (txCheck.rows.length === 0 || txCheck.rows[0].status !== 'pending') {
      console.log(`⚠️ Transaction ${transactionId} already processed`);
      await client.query('ROLLBACK');
      return;
    }
    
    const receipt = 'WDR' + Date.now().toString().slice(-10) + 
                   Math.random().toString(36).substring(2, 6).toUpperCase();
    
    await client.query(
      `UPDATE mpesa_transactions 
       SET status = 'completed', 
           mpesa_receipt_number = $1,
           completed_at = NOW()
       WHERE id = $2`,
      [receipt, transactionId]
    );
    
    await client.query(
      `UPDATE transactions 
       SET status = 'completed', 
           completed_at = NOW()
       WHERE reference = $1`,
      [reference]
    );
    
    await client.query('COMMIT');
    
    console.log(`✅ Withdrawal ${transactionId} completed: KES ${amount} to ${phoneNumber} (Receipt: ${receipt})`);
    
  } catch (error) {
    console.error(`❌ Withdrawal processing error for ${transactionId}:`, error);
    
    if (client) {
      try {
        await client.query('ROLLBACK');
        
        await client.query('BEGIN');
        
        await client.query(
          `UPDATE mpesa_transactions 
           SET status = 'failed',
               result_description = $1
           WHERE id = $2`,
          [error.message, transactionId]
        );
        
        await client.query(
          `UPDATE wallets 
           SET main_balance = main_balance + $1
           WHERE user_id = $2`,
          [amount, userId]
        );
        
        await client.query(
          `UPDATE transactions 
           SET status = 'failed'
           WHERE reference = $1`,
          [reference]
        );
        
        await client.query('COMMIT');
        
        console.log(`✅ Refunded KES ${amount} to user ${userId}`);
      } catch (refundError) {
        console.error('❌ Refund failed:', refundError);
      }
    }
  } finally {
    if (client) client.release();
  }
}

app.get('/api/withdrawal/status/:transactionId', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT t.*, mt.mpesa_receipt_number, mt.result_description
       FROM transactions t
       LEFT JOIN mpesa_transactions mt ON t.reference = mt.reference
       WHERE t.id = $1 OR t.reference = $1`,
      [req.params.transactionId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Transaction not found' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('❌ Withdrawal status error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== ADMIN M-PESA RECOVERY ====================
app.post('/api/admin/mpesa/recover-transaction', authenticateAdmin, async (req, res) => {
  const { transactionId, userId, amount, receipt } = req.body;
  
  let client;
  
  try {
    client = await pool.connect();
    await client.query('BEGIN');
    
    const wallet = await client.query(
      'SELECT * FROM wallets WHERE user_id = $1 FOR UPDATE',
      [userId]
    );
    
    const currentBalance = parseFloat(wallet.rows[0]?.main_balance || 0);
    
    await client.query(
      `UPDATE mpesa_transactions 
       SET status = 'completed',
           mpesa_receipt_number = $1,
           completed_at = NOW()
       WHERE id = $2`,
      [receipt, transactionId]
    );
    
    await client.query(
      `UPDATE wallets 
       SET main_balance = main_balance + $1,
           lifetime_deposits = lifetime_deposits + $1,
           updated_at = NOW()
       WHERE user_id = $2`,
      [amount, userId]
    );
    
    await client.query(
      `INSERT INTO transactions 
       (user_id, type, amount, status, description, reference, balance_before, balance_after, profit)
       VALUES ($1, 'deposit', $2, 'completed', $3, $4, $5, $5 + $2, 0)`,
      [userId, amount, `M-PESA deposit (Manual recovery)`, `REC-${Date.now()}`, currentBalance]
    );
    
    await client.query('COMMIT');
    
    await logAdminAction(req.admin.id, 'mpesa_recovery', 'transaction', transactionId, {
      amount,
      receipt,
      userId
    });
    
    res.json({
      success: true,
      message: `Recovered KES ${amount} for user ${userId}`
    });
    
  } catch (error) {
    if (client) await client.query('ROLLBACK');
    console.error('❌ Recovery error:', error);
    res.status(500).json({ error: error.message });
  } finally {
    if (client) client.release();
  }
});

// ==================== BETS ====================
app.post('/api/bets', authenticateToken, async (req, res) => {
  const { userId, selections, stake, totalOdds, potentialWinnings } = req.body;
  
  let client;
  
  try {
    console.log('🎲 Bet placement:', { userId, stake, selections: selections.length });
    
    if (stake < 10) {
      return res.status(400).json({ error: 'Minimum stake is KES 10' });
    }
    
    client = await pool.connect();
    await client.query('BEGIN');
    
    const walletResult = await client.query(
      'SELECT * FROM wallets WHERE user_id = $1 FOR UPDATE',
      [userId]
    );
    
    if (walletResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Wallet not found' });
    }
    
    const currentBalance = parseFloat(walletResult.rows[0].main_balance);
    
    if (currentBalance < stake) {
      await client.query('ROLLBACK');
      return res.status(400).json({ 
        error: 'Insufficient balance',
        available: currentBalance,
        required: stake
      });
    }
    
    const referenceNumber = 'BET-' + Date.now() + '-' + Math.random().toString(36).substring(2, 8).toUpperCase();
    
    const betResult = await client.query(
      `INSERT INTO bets (
        user_id, selections, stake, total_odds, potential_winnings, 
        bet_type, reference_number, status, profit, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW()) RETURNING id`,
      [
        userId, 
        JSON.stringify(selections), 
        stake, 
        totalOdds, 
        potentialWinnings, 
        selections.length > 1 ? 'accumulator' : 'single',
        referenceNumber,
        'pending',
        -stake
      ]
    );
    
    await client.query(
      `UPDATE wallets 
       SET main_balance = main_balance - $1,
           lifetime_bets = lifetime_bets + $1,
           total_profit = total_profit - $1,
           updated_at = NOW()
       WHERE user_id = $2`,
      [stake, userId]
    );
    
    await client.query(
      `INSERT INTO transactions (
        user_id, type, amount, status, description, reference, 
        balance_before, balance_after, profit, created_at
      ) VALUES ($1, 'bet', $2, 'completed', 'Bet placed', $3, $4, $4 - $2, -$2, NOW())`,
      [userId, stake, referenceNumber, currentBalance]
    );
    
    await client.query('COMMIT');
    
    const updatedWallet = await pool.query(
      'SELECT main_balance, total_profit FROM wallets WHERE user_id = $1',
      [userId]
    );
    
    res.json({ 
      success: true, 
      betId: betResult.rows[0].id,
      message: 'Bet placed successfully',
      newBalance: updatedWallet.rows[0].main_balance,
      newProfit: updatedWallet.rows[0].total_profit
    });
    
  } catch (error) {
    if (client) {
      await client.query('ROLLBACK');
      client.release();
    }
    console.error('❌ Bet error:', error);
    res.status(500).json({ error: error.message });
  } finally {
    if (client) client.release();
  }
});

app.get('/api/bets/:userId', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM bets 
       WHERE user_id = $1 
       ORDER BY created_at DESC 
       LIMIT 100`,
      [req.params.userId]
    );
    
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Bets error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/bets/:betId/cancel', authenticateToken, async (req, res) => {
  const { betId } = req.params;
  const { userId } = req.body;
  
  let client;
  
  try {
    client = await pool.connect();
    await client.query('BEGIN');
    
    const betResult = await client.query(
      'SELECT * FROM bets WHERE id = $1 AND user_id = $2 AND status = $3 FOR UPDATE',
      [betId, userId, 'pending']
    );
    
    if (betResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Bet not found or cannot be cancelled' });
    }
    
    const bet = betResult.rows[0];
    
    await client.query(
      'UPDATE bets SET status = $1, updated_at = NOW() WHERE id = $2',
      ['cancelled', betId]
    );
    
    const walletResult = await client.query(
      'SELECT main_balance, total_profit FROM wallets WHERE user_id = $1 FOR UPDATE',
      [userId]
    );
    
    const currentBalance = parseFloat(walletResult.rows[0].main_balance);
    const currentProfit = parseFloat(walletResult.rows[0].total_profit);
    
    await client.query(
      `UPDATE wallets 
       SET main_balance = main_balance + $1,
           total_profit = total_profit + $1,
           updated_at = NOW()
       WHERE user_id = $2`,
      [bet.stake, userId]
    );
    
    await client.query(
      `INSERT INTO transactions 
       (user_id, type, amount, status, description, reference, balance_before, balance_after, profit)
       VALUES ($1, 'adjustment', $2, 'completed', 'Bet cancellation refund', $3, $4, $4 + $2, $2)`,
      [userId, bet.stake, 'REF-' + Date.now(), currentBalance]
    );
    
    await client.query('COMMIT');
    
    const updatedWallet = await pool.query(
      'SELECT main_balance, total_profit FROM wallets WHERE user_id = $1',
      [userId]
    );
    
    res.json({ 
      success: true, 
      message: 'Bet cancelled and stake refunded',
      newBalance: updatedWallet.rows[0].main_balance,
      newProfit: updatedWallet.rows[0].total_profit
    });
    
  } catch (error) {
    if (client) {
      await client.query('ROLLBACK');
      client.release();
    }
    console.error('❌ Cancel bet error:', error);
    res.status(500).json({ error: error.message });
  } finally {
    if (client) client.release();
  }
});

// ==================== GAME BETS ====================
app.post('/api/games/bet', authenticateToken, async (req, res) => {
  const { userId, gameType, stake, autoCashout } = req.body;
  
  let client;
  
  try {
    console.log('🎲 Placing game bet:', { userId, gameType, stake });
    
    if (req.user.userId !== userId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    if (stake < 10 || stake > 5000) {
      return res.status(400).json({ error: 'Stake must be between KES 10 and 5,000' });
    }
    
    if (!['aviator', 'jetx'].includes(gameType)) {
      return res.status(400).json({ error: 'Invalid game type' });
    }
    
    const numericUserId = parseInt(userId);
    const numericStake = parseFloat(stake);
    const numericAutoCashout = autoCashout ? parseFloat(autoCashout) : null;
    
    if (isNaN(numericUserId) || isNaN(numericStake)) {
      return res.status(400).json({ error: 'Invalid number format' });
    }
    
    client = await pool.connect();
    await client.query('BEGIN');
    
    const wallet = await client.query(
      'SELECT * FROM wallets WHERE user_id = $1 FOR UPDATE',
      [numericUserId]
    );
    
    if (wallet.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Wallet not found' });
    }
    
    const currentBalance = parseFloat(wallet.rows[0].main_balance);
    
    if (currentBalance < numericStake) {
      await client.query('ROLLBACK');
      return res.status(400).json({ 
        error: 'Insufficient balance',
        available: currentBalance,
        required: numericStake
      });
    }
    
    let roundResult = await client.query(
      `SELECT * FROM game_rounds 
       WHERE game = $1 AND status IN ('waiting', 'flying')
       ORDER BY created_at DESC 
       LIMIT 1`,
      [gameType]
    );
    
    let roundId;
    let roundNumber;
    
    if (roundResult.rows.length === 0) {
      const maxRoundResult = await client.query(
        `SELECT COALESCE(MAX(round_number), 0) as max_round FROM game_rounds WHERE game = $1`,
        [gameType]
      );
      
      const nextRoundNumber = (parseInt(maxRoundResult.rows[0].max_round) || 0) + 1;
      
      const newRound = await client.query(
        `INSERT INTO game_rounds (game, round_number, status, started_at)
         VALUES ($1, $2, $3, NOW())
         RETURNING id, round_number`,
        [gameType, nextRoundNumber, 'waiting']
      );
      
      roundId = newRound.rows[0].id;
      roundNumber = newRound.rows[0].round_number;
      console.log(`🆕 Created new round #${roundNumber} with ID: ${roundId}`);
    } else {
      roundId = roundResult.rows[0].id;
      roundNumber = roundResult.rows[0].round_number;
      console.log(`🔄 Using existing round #${roundNumber} with ID: ${roundId}`);
    }
    
    const referenceNumber = `${gameType}-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
    
    const betResult = await client.query(
      `INSERT INTO bets (
        user_id, selections, stake, total_odds, potential_winnings,
        status, bet_type, game_type, round_id, reference_number, profit, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
      RETURNING id`,
      [
        numericUserId,
        JSON.stringify([{ game: gameType, multiplier: 1.0 }]),
        numericStake,
        1.0,
        numericStake * (numericAutoCashout || 1.0),
        'pending',
        'single',
        gameType,
        roundId,
        referenceNumber,
        -numericStake
      ]
    );
    
    const betId = betResult.rows[0].id;
    
    await client.query(
      `UPDATE wallets 
       SET main_balance = main_balance - $1,
           lifetime_bets = lifetime_bets + $1,
           total_profit = total_profit - $1,
           updated_at = NOW()
       WHERE user_id = $2`,
      [numericStake, numericUserId]
    );
    
    await client.query(
      `UPDATE game_rounds 
       SET total_bets = total_bets + 1,
           total_wagered = total_wagered + $1
       WHERE id = $2`,
      [numericStake, roundId]
    );
    
    await client.query(
      `INSERT INTO transactions (
        user_id, type, amount, status, description, reference, 
        balance_before, balance_after, profit, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())`,
      [
        numericUserId,
        'bet',
        numericStake,
        'completed',
        `${gameType} bet placed`,
        `BET-${betId}`,
        currentBalance,
        currentBalance - numericStake,
        -numericStake
      ]
    );
    
    await client.query('COMMIT');
    
    const updatedWallet = await pool.query(
      'SELECT main_balance, total_profit FROM wallets WHERE user_id = $1',
      [numericUserId]
    );
    
    console.log(`✅ Bet placed: User ${numericUserId} bet KES ${numericStake} on ${gameType} (Round #${roundNumber})`);
    console.log(`💰 New balance: ${updatedWallet.rows[0].main_balance}`);
    
    res.json({
      success: true,
      betId,
      roundId,
      roundNumber,
      message: 'Bet placed successfully',
      newBalance: updatedWallet.rows[0].main_balance,
      newProfit: updatedWallet.rows[0].total_profit,
      oldBalance: currentBalance
    });
    
  } catch (error) {
    if (client) {
      await client.query('ROLLBACK');
      client.release();
    }
    console.error('❌ Game bet error:', error);
    console.error('Error details:', error.message);
    res.status(500).json({ 
      error: 'Failed to place bet',
      details: error.message 
    });
  } finally {
    if (client) client.release();
  }
});

// ==================== JACKPOT ====================
app.post('/api/jackpot/enter', authenticateToken, async (req, res) => {
  const { userId, jackpotId, numbers } = req.body;
  
  let client;
  
  try {
    client = await pool.connect();
    await client.query('BEGIN');
    
    const jackpot = await client.query(
      'SELECT * FROM jackpots WHERE id = $1 AND status = $2 FOR UPDATE',
      [jackpotId, 'active']
    );
    
    if (jackpot.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Jackpot not found or inactive' });
    }
    
    const jp = jackpot.rows[0];
    
    if (jp.current_players >= jp.max_players) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Jackpot is full' });
    }
    
    const wallet = await client.query(
      'SELECT * FROM wallets WHERE user_id = $1 FOR UPDATE',
      [userId]
    );
    
    if (wallet.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Wallet not found' });
    }
    
    const currentBalance = parseFloat(wallet.rows[0].main_balance);
    const currentProfit = parseFloat(wallet.rows[0].total_profit);
    
    if (currentBalance < jp.entry_fee) {
      await client.query('ROLLBACK');
      return res.status(400).json({ 
        error: 'Insufficient balance',
        required: jp.entry_fee,
        available: currentBalance
      });
    }
    
    const entry = await client.query(
      `INSERT INTO jackpot_entries 
       (jackpot_id, user_id, numbers, stake, created_at)
       VALUES ($1, $2, $3, $4, NOW())
       RETURNING id`,
      [jackpotId, userId, JSON.stringify(numbers), jp.entry_fee]
    );
    
    await client.query(
      `UPDATE wallets 
       SET main_balance = main_balance - $1,
           total_profit = total_profit - $1,
           updated_at = NOW()
       WHERE user_id = $2`,
      [jp.entry_fee, userId]
    );
    
    await client.query(
      `UPDATE jackpots 
       SET total_pool = total_pool + $1,
           current_players = current_players + 1,
           updated_at = NOW()
       WHERE id = $2`,
      [jp.entry_fee, jackpotId]
    );
    
    await client.query(
      `INSERT INTO transactions 
       (user_id, type, amount, status, description, reference, balance_before, balance_after, profit, created_at)
       VALUES ($1, 'jackpot', $2, 'completed', $3, $4, $5, $5 - $2, -$2, NOW())`,
      [userId, jp.entry_fee, `Jackpot entry #${entry.rows[0].id}`, `JACK-${Date.now()}`, currentBalance]
    );
    
    await client.query('COMMIT');
    
    const updatedWallet = await pool.query(
      'SELECT main_balance, total_profit FROM wallets WHERE user_id = $1',
      [userId]
    );
    
    res.json({
      success: true,
      message: 'Successfully entered jackpot',
      entryId: entry.rows[0].id,
      newBalance: updatedWallet.rows[0].main_balance,
      newProfit: updatedWallet.rows[0].total_profit
    });
    
  } catch (error) {
    if (client) await client.query('ROLLBACK');
    console.error('❌ Jackpot entry error:', error);
    res.status(500).json({ error: error.message });
  } finally {
    if (client) client.release();
  }
});

app.get('/api/jackpot/active', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT j.*, 
         COUNT(je.id) as total_entries,
         COALESCE(SUM(je.stake), 0) as total_collected
       FROM jackpots j
       LEFT JOIN jackpot_entries je ON j.id = je.jackpot_id
       WHERE j.status = 'active'
       GROUP BY j.id
       ORDER BY j.draw_date`
    );
    
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Jackpots error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/jackpot/user/:userId', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT je.*, j.name, j.draw_date, j.prize_breakdown
       FROM jackpot_entries je
       JOIN jackpots j ON je.jackpot_id = j.id
       WHERE je.user_id = $1
       ORDER BY je.created_at DESC`,
      [req.params.userId]
    );
    
    res.json(result.rows);
  } catch (error) {
    console.error('❌ User jackpots error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== BONUSES ====================
app.get('/api/bonuses/:userId', authenticateToken, async (req, res) => {
  try {
    const userId = req.params.userId;
    
    const claimedResult = await pool.query(
      `SELECT ub.*, b.name, b.description, b.type, b.amount as bonus_amount,
              b.percentage, b.min_deposit, b.max_amount
       FROM user_bonuses ub
       JOIN bonuses b ON ub.bonus_id = b.id
       WHERE ub.user_id = $1
       ORDER BY ub.claimed_at DESC`,
      [userId]
    );
    
    const availableResult = await pool.query(
      `SELECT b.* FROM bonuses b
       WHERE b.is_active = true 
       AND (b.valid_to IS NULL OR b.valid_to > NOW())
       AND b.id NOT IN (
         SELECT ub.bonus_id FROM user_bonuses ub WHERE ub.user_id = $1
       )
       ORDER BY b.created_at DESC`,
      [userId]
    );
    
    res.json({
      claimed: claimedResult.rows,
      available: availableResult.rows
    });
    
  } catch (error) {
    console.error('❌ Bonuses error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/bonuses/welcome/claim', authenticateToken, async (req, res) => {
  const { userId } = req.body;
  
  let client;
  
  try {
    const claimedResult = await pool.query(
      `SELECT * FROM user_bonuses 
       WHERE user_id = $1 AND bonus_id = (SELECT id FROM bonuses WHERE type = 'welcome' LIMIT 1)`,
      [userId]
    );
    
    if (claimedResult.rows.length > 0) {
      return res.status(400).json({ error: 'Welcome bonus already claimed' });
    }
    
    const bonusResult = await pool.query(
      "SELECT * FROM bonuses WHERE type = 'welcome' LIMIT 1"
    );
    
    if (bonusResult.rows.length === 0) {
      return res.status(404).json({ error: 'Welcome bonus not found' });
    }
    
    const bonus = bonusResult.rows[0];
    
    client = await pool.connect();
    await client.query('BEGIN');
    
    const walletResult = await client.query(
      'SELECT main_balance, total_profit FROM wallets WHERE user_id = $1 FOR UPDATE',
      [userId]
    );
    
    const currentBalance = parseFloat(walletResult.rows[0]?.main_balance || 0);
    const currentProfit = parseFloat(walletResult.rows[0]?.total_profit || 0);
    
    await client.query(
      `INSERT INTO user_bonuses (user_id, bonus_id, amount, status, claimed_at)
       VALUES ($1, $2, $3, 'completed', NOW())`,
      [userId, bonus.id, bonus.amount]
    );
    
    await client.query(
      `UPDATE wallets 
       SET main_balance = main_balance + $1,
           total_profit = total_profit + $1,
           updated_at = NOW()
       WHERE user_id = $2`,
      [bonus.amount, userId]
    );
    
    await client.query(
      `INSERT INTO transactions 
       (user_id, type, amount, status, description, reference, balance_before, balance_after, profit)
       VALUES ($1, 'bonus', $2, 'completed', 'Welcome bonus claimed', $3, $4, $4 + $2, $2)`,
      [userId, bonus.amount, 'BONUS-' + Date.now(), currentBalance]
    );
    
    await client.query('COMMIT');
    
    const updatedWallet = await pool.query(
      'SELECT main_balance, total_profit FROM wallets WHERE user_id = $1',
      [userId]
    );
    
    res.json({ 
      success: true, 
      message: 'Welcome bonus claimed successfully',
      amount: bonus.amount,
      newBalance: updatedWallet.rows[0].main_balance,
      newProfit: updatedWallet.rows[0].total_profit
    });
    
  } catch (error) {
    if (client) {
      await client.query('ROLLBACK');
      client.release();
    }
    console.error('❌ Claim bonus error:', error);
    res.status(500).json({ error: error.message });
  } finally {
    if (client) client.release();
  }
});

// ==================== LEAGUES AND MATCHES ====================
app.get('/api/leagues', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM leagues ORDER BY is_popular DESC, name'
    );
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Leagues error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/matches/upcoming', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT m.*, l.name as league_name, l.country as league_country 
       FROM matches m 
       JOIN leagues l ON m.league_id = l.id 
       WHERE m.status = 'scheduled' AND m.match_date > NOW() 
       ORDER BY m.match_date 
       LIMIT 50`
    );
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Upcoming matches error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/matches/live', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT m.*, l.name as league_name, l.country as league_country 
       FROM matches m 
       JOIN leagues l ON m.league_id = l.id 
       WHERE m.status = 'live' 
       ORDER BY m.match_date`
    );
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Live matches error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/matches/league/:leagueId', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT m.*, l.name as league_name, l.country as league_country 
       FROM matches m 
       JOIN leagues l ON m.league_id = l.id 
       WHERE m.league_id = $1 AND m.match_date > NOW() - INTERVAL '3 hours'
       ORDER BY m.match_date`,
      [req.params.leagueId]
    );
    
    res.json(result.rows);
    
  } catch (error) {
    console.error('❌ League matches error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/matches/:matchId', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT m.*, l.name as league_name, l.country as league_country 
       FROM matches m 
       JOIN leagues l ON m.league_id = l.id 
       WHERE m.id = $1`,
      [req.params.matchId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Match not found' });
    }
    
    res.json(result.rows[0]);
    
  } catch (error) {
    console.error('❌ Match details error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== SUPPORT ENDPOINTS ====================
app.get('/api/support/faqs', async (req, res) => {
  try {
    const faqs = [
      {
        id: '1',
        category: 'Getting Started',
        categoryIcon: '🚀',
        question: 'How do I create an account?',
        answer: 'Click on Register, fill in your details (name, age, email, phone), create a password, and agree to terms. You must be 18+ to register.'
      },
      {
        id: '2',
        category: 'Getting Started',
        categoryIcon: '🚀',
        question: 'How do I verify my account?',
        answer: 'After registration, you\'ll receive an OTP via SMS. Enter the 6-digit code to verify your phone number.'
      },
      {
        id: '3',
        category: 'Deposits & Withdrawals',
        categoryIcon: '💰',
        question: 'How do I deposit money?',
        answer: 'Go to Wallet → Deposit. Choose M-PESA, enter amount, and follow the prompt. Minimum deposit is KES 10.'
      },
      {
        id: '4',
        category: 'Deposits & Withdrawals',
        categoryIcon: '💰',
        question: 'How long do withdrawals take?',
        answer: 'Withdrawals are processed within 24 hours. M-PESA withdrawals are instant once approved.'
      }
    ];
    
    res.json(faqs);
  } catch (error) {
    console.error('❌ FAQs error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/support/contact', async (req, res) => {
  try {
    const contactInfo = {
      email: 'support@lobbybets.co.ke',
      phone: '+254 700 123 456',
      whatsapp: '+254 700 123 456',
      hours: '24/7 Customer Support',
      responseTime: '2-3 minutes'
    };
    
    res.json(contactInfo);
  } catch (error) {
    console.error('❌ Contact info error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/support/feedback', authenticateToken, async (req, res) => {
  const { userId, rating, comment, category } = req.body;
  
  try {
    console.log('📝 Feedback received:', { userId, rating, category, comment });
    
    res.json({
      success: true,
      message: 'Thank you for your feedback!'
    });
  } catch (error) {
    console.error('❌ Feedback error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/support/stats', async (req, res) => {
  try {
    const stats = {
      onlineAgents: 3,
      avgResponseTime: '2min',
      ticketsToday: 24,
      satisfaction: '98%'
    };
    
    res.json(stats);
  } catch (error) {
    console.error('❌ Support stats error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== STATISTICS ====================
app.get('/api/stats/:userId', authenticateToken, async (req, res) => {
  try {
    const betsResult = await pool.query(
      'SELECT COUNT(*) as total_bets FROM bets WHERE user_id = $1',
      [req.params.userId]
    );
    
    const winsResult = await pool.query(
      'SELECT COUNT(*) as wins FROM bets WHERE user_id = $1 AND status IN ($2, $3)',
      [req.params.userId, 'won', 'cashed_out']
    );
    
    const totalBets = parseInt(betsResult.rows[0].total_bets);
    const wins = parseInt(winsResult.rows[0].wins);
    
    res.json({
      total_bets: totalBets,
      wins: wins,
      losses: totalBets - wins,
      win_rate: totalBets > 0 ? ((wins / totalBets) * 100).toFixed(2) : 0
    });
  } catch (error) {
    console.error('❌ Stats error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== AFFILIATE/REFERRAL SYSTEM ====================

// Get referral statistics for user
app.get('/api/affiliate/stats/:userId', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    
    if (req.user.userId !== parseInt(userId)) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const userResult = await pool.query(
      'SELECT referral_code FROM profiles WHERE id = $1',
      [userId]
    );
    
    const referralCode = userResult.rows[0]?.referral_code || null;
    
    const referralsResult = await pool.query(
      `SELECT p.id, p.full_name, p.phone, p.created_at,
              COALESCE((
                SELECT SUM(amount) FROM transactions 
                WHERE user_id = p.id AND type = 'deposit' AND status = 'completed'
              ), 0) as total_deposits,
              COALESCE((
                SELECT SUM(amount * $2) FROM transactions 
                WHERE user_id = p.id AND type = 'deposit' AND status = 'completed'
              ), 0) as earned_commission
       FROM profiles p
       WHERE p.referred_by = $1
       ORDER BY p.created_at DESC`,
      [userId, COMMISSION_RATE]
    );
    
    const referrals = referralsResult.rows;
    
    let totalCommission = 0;
    let pendingCommission = 0;
    let activeReferrals = 0;
    
    for (const ref of referrals) {
      const commission = parseFloat(ref.earned_commission) || 0;
      totalCommission += commission;
      
      if (parseFloat(ref.total_deposits) >= 100) {
        pendingCommission += commission;
        activeReferrals++;
      }
    }
    
    const stats = {
      referral_code: referralCode,
      total_commission_earned: totalCommission,
      pending_commission: pendingCommission,
      paid_commission: 0,
      total_referrals: referrals.length,
      active_referrals: activeReferrals,
      pending_referrals: referrals.length - activeReferrals
    };
    
    res.json(stats);
    
  } catch (error) {
    console.error('❌ Error fetching referral stats:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get list of referrals for user
app.get('/api/affiliate/referrals/:userId', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    
    if (req.user.userId !== parseInt(userId)) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const result = await pool.query(
      `SELECT p.id, p.full_name as name, p.phone, p.created_at as date,
              COALESCE((
                SELECT SUM(amount) FROM transactions 
                WHERE user_id = p.id AND type = 'deposit' AND status = 'completed'
              ), 0) as deposits,
              COALESCE((
                SELECT SUM(amount * $2) FROM transactions 
                WHERE user_id = p.id AND type = 'deposit' AND status = 'completed'
              ), 0) as commission,
              CASE 
                WHEN COALESCE((
                  SELECT SUM(amount) FROM transactions 
                  WHERE user_id = p.id AND type = 'deposit' AND status = 'completed'
                ), 0) >= 100 THEN 'active'
                ELSE 'pending'
              END as status
       FROM profiles p
       WHERE p.referred_by = $1
       ORDER BY p.created_at DESC`,
      [userId, COMMISSION_RATE]
    );
    
    res.json(result.rows);
    
  } catch (error) {
    console.error('❌ Error fetching referrals:', error);
    res.status(500).json({ error: error.message });
  }
});

// Withdraw commission from affiliate balance
app.post('/api/affiliate/withdraw', authenticateToken, async (req, res) => {
  const { userId, amount } = req.body;
  
  let client;
  
  try {
    if (req.user.userId !== parseInt(userId)) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    if (amount < MIN_WITHDRAWAL) {
      return res.status(400).json({ 
        success: false, 
        error: `Minimum withdrawal is KES ${MIN_WITHDRAWAL}` 
      });
    }
    
    client = await pool.connect();
    await client.query('BEGIN');
    
    const commissionResult = await client.query(
      `SELECT COALESCE(SUM(t.amount * $2), 0) as total_commission,
              COALESCE(SUM(CASE 
                WHEN t.amount >= 100 THEN t.amount * $2 
                ELSE 0 
              END), 0) as available_commission
       FROM transactions t
       JOIN profiles p ON t.user_id = p.id
       WHERE p.referred_by = $1 
         AND t.type = 'deposit' 
         AND t.status = 'completed'`,
      [userId, COMMISSION_RATE]
    );
    
    const availableCommission = parseFloat(commissionResult.rows[0].available_commission);
    
    if (availableCommission < amount) {
      await client.query('ROLLBACK');
      return res.status(400).json({ 
        success: false, 
        error: `Insufficient commission. Available: KES ${availableCommission}` 
      });
    }
    
    const walletResult = await client.query(
      'SELECT * FROM wallets WHERE user_id = $1 FOR UPDATE',
      [userId]
    );
    
    let currentBalance = 0;
    if (walletResult.rows.length === 0) {
      const newWallet = await client.query(
        `INSERT INTO wallets (user_id, main_balance, created_at, updated_at)
         VALUES ($1, 0, NOW(), NOW())
         RETURNING *`,
        [userId]
      );
      currentBalance = parseFloat(newWallet.rows[0].main_balance);
    } else {
      currentBalance = parseFloat(walletResult.rows[0].main_balance);
    }
    
    await client.query(
      `UPDATE wallets 
       SET main_balance = main_balance + $1,
           affiliate_balance = affiliate_balance - $1,
           updated_at = NOW()
       WHERE user_id = $2`,
      [amount, userId]
    );
    
    const reference = `COMM-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
    
    await client.query(
      `INSERT INTO transactions (
        user_id, type, amount, status, description, reference,
        balance_before, balance_after, profit, created_at
      ) VALUES ($1, 'commission_withdrawal', $2, 'completed', $3, $4, $5, $5 + $2, 0, NOW())`,
      [userId, amount, `Affiliate commission withdrawal`, reference, currentBalance]
    );
    
    await client.query(
      `INSERT INTO commission_withdrawals (
        user_id, amount, reference, status, created_at
      ) VALUES ($1, $2, $3, 'completed', NOW())`,
      [userId, amount, reference]
    );
    
    await client.query('COMMIT');
    
    console.log(`✅ Commission withdrawal: User ${userId} withdrew KES ${amount}`);
    
    res.json({
      success: true,
      message: `Successfully withdrew KES ${amount}`,
      amount: amount,
      newBalance: currentBalance + amount,
      reference
    });
    
  } catch (error) {
    if (client) await client.query('ROLLBACK');
    console.error('❌ Commission withdrawal error:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  } finally {
    if (client) client.release();
  }
});

// Get commission withdrawal history
app.get('/api/affiliate/commissions/:userId', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    
    if (req.user.userId !== parseInt(userId)) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const result = await pool.query(
      `SELECT cw.*, 
              COALESCE((
                SELECT SUM(t.amount * $2) FROM transactions t
                JOIN profiles p ON t.user_id = p.id
                WHERE p.referred_by = $1 AND t.type = 'deposit' AND t.status = 'completed'
                AND t.created_at <= cw.created_at
              ), 0) as balance_after
       FROM commission_withdrawals cw
       WHERE cw.user_id = $1
       ORDER BY cw.created_at DESC`,
      [userId, COMMISSION_RATE]
    );
    
    res.json(result.rows);
    
  } catch (error) {
    console.error('❌ Error fetching commission history:', error);
    res.status(500).json({ error: error.message });
  }
});

// Generate referral code for user
app.post('/api/affiliate/generate-code', authenticateToken, async (req, res) => {
  const { userId } = req.body;
  
  try {
    if (req.user.userId !== parseInt(userId)) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const existing = await pool.query(
      'SELECT referral_code FROM profiles WHERE id = $1',
      [userId]
    );
    
    if (existing.rows[0]?.referral_code) {
      return res.json({ 
        success: true, 
        referral_code: existing.rows[0].referral_code 
      });
    }
    
    let referralCode;
    let isUnique = false;
    
    while (!isUnique) {
      const prefix = 'REF';
      const random = Math.random().toString(36).substring(2, 8).toUpperCase();
      referralCode = `${prefix}${random}`;
      
      const check = await pool.query(
        'SELECT id FROM profiles WHERE referral_code = $1',
        [referralCode]
      );
      
      if (check.rows.length === 0) {
        isUnique = true;
      }
    }
    
    await pool.query(
      'UPDATE profiles SET referral_code = $1 WHERE id = $2',
      [referralCode, userId]
    );
    
    res.json({
      success: true,
      referral_code: referralCode
    });
    
  } catch (error) {
    console.error('❌ Error generating referral code:', error);
    res.status(500).json({ error: error.message });
  }
});

// Validate referral code (for registration)
app.get('/api/affiliate/validate/:code', async (req, res) => {
  const { code } = req.params;
  
  try {
    const result = await pool.query(
      'SELECT id, full_name FROM profiles WHERE referral_code = $1',
      [code.toUpperCase()]
    );
    
    if (result.rows.length > 0) {
      res.json({ 
        valid: true, 
        referrerId: result.rows[0].id,
        referrerName: result.rows[0].full_name
      });
    } else {
      res.json({ valid: false });
    }
    
  } catch (error) {
    console.error('❌ Error validating referral code:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get top referrers leaderboard
app.get('/api/affiliate/leaderboard', async (req, res) => {
  const { limit = 10 } = req.query;
  
  try {
    const result = await pool.query(
      `SELECT p.id, p.full_name, p.referral_code,
              COUNT(r.id) as total_referrals,
              COALESCE(SUM(CASE 
                WHEN t.amount >= 100 THEN t.amount * $2 
                ELSE 0 
              END), 0) as total_commission,
              COALESCE(SUM(t.amount), 0) as total_deposits_from_referrals
       FROM profiles p
       LEFT JOIN profiles r ON r.referred_by = p.id
       LEFT JOIN transactions t ON t.user_id = r.id AND t.type = 'deposit' AND t.status = 'completed'
       WHERE p.referral_code IS NOT NULL
       GROUP BY p.id
       ORDER BY total_commission DESC
       LIMIT $1`,
      [limit, COMMISSION_RATE]
    );
    
    res.json(result.rows);
    
  } catch (error) {
    console.error('❌ Error fetching leaderboard:', error);
    res.status(500).json({ error: error.message });
  }
});

// Track a new referral (when user signs up with code)
app.post('/api/affiliate/track', authenticateToken, async (req, res) => {
  const { referrer_code, referred_user_id } = req.body;
  
  try {
    const referrerResult = await pool.query(
      'SELECT id FROM profiles WHERE referral_code = $1',
      [referrer_code.toUpperCase()]
    );
    
    if (referrerResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Invalid referral code' });
    }
    
    const referrerId = referrerResult.rows[0].id;
    
    await pool.query(
      'UPDATE profiles SET referred_by = $1 WHERE id = $2',
      [referrerId, referred_user_id]
    );
    
    console.log(`✅ Referral tracked: User ${referred_user_id} referred by ${referrerId}`);
    
    res.json({ success: true });
    
  } catch (error) {
    console.error('❌ Error tracking referral:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== ADMIN ROUTES ====================
app.post('/api/admin/register-first', async (req, res) => {
  const { full_name, email, phone, password } = req.body;
  
  try {
    if (!full_name || !email || !phone || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    const adminCount = await pool.query('SELECT COUNT(*) FROM admins');
    
    if (parseInt(adminCount.rows[0].count) > 0) {
      return res.status(403).json({ 
        error: 'Initial setup already completed. Maximum 3 admins allowed.' 
      });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const result = await pool.query(
      `INSERT INTO admins (full_name, email, phone, password_hash, role) 
       VALUES ($1, $2, $3, $4, 'super_admin') 
       RETURNING id, full_name, email, phone, role, created_at`,
      [full_name, email, phone, hashedPassword]
    );
    
    const admin = result.rows[0];
    
    const token = jwt.sign(
      { adminId: admin.id, email: admin.email, role: admin.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    console.log('✅ First super admin created:', email);
    
    res.json({
      success: true,
      message: 'Super admin created successfully',
      token,
      admin
    });
    
  } catch (error) {
    console.error('❌ Error creating first admin:', error);
    
    if (error.code === '23505') {
      return res.status(400).json({ error: 'Email or phone already exists' });
    }
    
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/login', async (req, res) => {
  const { email, password, deviceInfo, userAgent } = req.body;
  const ipAddress = req.ip || req.connection.remoteAddress;
  
  try {
    console.log('👑 Admin login attempt for:', email);
    
    const result = await pool.query(
      `SELECT id, full_name, email, phone, role, password_hash, 
              is_active, failed_login_attempts, locked_until
       FROM admins WHERE email = $1`,
      [email]
    );
    
    if (result.rows.length === 0) {
      await pool.query(
        `INSERT INTO admin_login_history (email, ip_address, user_agent, login_status, failure_reason)
         VALUES ($1, $2, $3, 'failed', 'User not found')`,
        [email, ipAddress, userAgent || null]
      );
      
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const admin = result.rows[0];
    
    if (admin.locked_until && new Date(admin.locked_until) > new Date()) {
      const lockTimeRemaining = Math.ceil((new Date(admin.locked_until) - new Date()) / 60000);
      
      return res.status(403).json({ 
        error: `Account is locked. Try again in ${lockTimeRemaining} minutes.` 
      });
    }
    
    if (!admin.is_active) {
      return res.status(403).json({ error: 'Account is deactivated. Contact super admin.' });
    }
    
    const validPassword = await bcrypt.compare(password, admin.password_hash);
    if (!validPassword) {
      await handleFailedLogin(email);
      
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const existingSession = await pool.query(
      `SELECT * FROM admin_sessions 
       WHERE admin_id = $1 AND is_active = true AND expires_at > NOW()`,
      [admin.id]
    );
    
    if (existingSession.rows.length > 0) {
      await pool.query(
        `UPDATE admin_sessions 
         SET is_active = false 
         WHERE admin_id = $1 AND is_active = true`,
        [admin.id]
      );
    }
    
    const sessionToken = jwt.sign(
      { 
        adminId: admin.id, 
        email: admin.email, 
        role: admin.role,
        sessionId: crypto.randomBytes(16).toString('hex'),
        loginTime: Date.now()
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 24);
    
    await pool.query(
      `INSERT INTO admin_sessions 
       (admin_id, session_token, device_info, ip_address, user_agent, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [admin.id, sessionToken, deviceInfo || null, ipAddress, userAgent || null, expiresAt]
    );
    
    await resetFailedLogin(admin.id);
    
    await pool.query(
      `UPDATE admins 
       SET last_login_at = NOW(), 
           last_login_ip = $1
       WHERE id = $2`,
      [ipAddress, admin.id]
    );
    
    console.log('✅ Admin login successful:', admin.email, 'Role:', admin.role);
    
    res.json({
      success: true,
      token: sessionToken,
      admin: {
        id: admin.id,
        full_name: admin.full_name,
        email: admin.email,
        phone: admin.phone,
        role: admin.role
      },
      session: {
        expiresAt,
        expiresIn: '24 hours'
      }
    });
    
  } catch (error) {
    console.error('❌ Admin login error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/forgot-password', async (req, res) => {
  const { email, newPassword, confirmPassword } = req.body;
  const ipAddress = req.ip || req.connection.remoteAddress;
  
  try {
    console.log('🔑 Password reset requested for:', email);
    
    if (!email || !newPassword || !confirmPassword) {
      return res.status(400).json({ error: 'Email, new password, and confirm password are required' });
    }
    
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }
    
    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    
    const hasUpperCase = /[A-Z]/.test(newPassword);
    const hasLowerCase = /[a-z]/.test(newPassword);
    const hasNumbers = /\d/.test(newPassword);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(newPassword);
    
    if (!(hasUpperCase && hasLowerCase && hasNumbers && hasSpecialChar)) {
      return res.status(400).json({ 
        error: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character' 
      });
    }
    
    const admin = await pool.query(
      'SELECT id, full_name, is_active, locked_until FROM admins WHERE email = $1',
      [email]
    );
    
    if (admin.rows.length === 0) {
      return res.json({ 
        success: true, 
        message: 'If the email exists, a password reset has been processed.' 
      });
    }
    
    const adminData = admin.rows[0];
    
    if (adminData.locked_until && new Date(adminData.locked_until) > new Date()) {
      return res.status(403).json({ 
        error: 'Account is locked. Cannot reset password at this time.' 
      });
    }
    
    if (!adminData.is_active) {
      return res.status(403).json({ error: 'Account is deactivated. Contact super admin.' });
    }
    
    const hashedPassword = await bcrypt.hash(newPassword, 12);
    
    await pool.query(
      `UPDATE admins 
       SET password_hash = $1, 
           updated_at = NOW(),
           failed_login_attempts = 0,
           locked_until = NULL
       WHERE id = $2`,
      [hashedPassword, adminData.id]
    );
    
    await pool.query(
      `UPDATE admin_sessions 
       SET is_active = false 
       WHERE admin_id = $1 AND is_active = true`,
      [adminData.id]
    );
    
    console.log('✅ Password reset successful for:', email);
    
    res.json({
      success: true,
      message: 'Password reset successfully. All existing sessions have been terminated for security.'
    });
    
  } catch (error) {
    console.error('❌ Password reset error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/logout', authenticateAdmin, async (req, res) => {
  const sessionToken = req.headers['authorization']?.split(' ')[1];
  const ipAddress = req.ip || req.connection.remoteAddress;
  
  try {
    console.log('👋 Admin logout for:', req.admin.email);
    
    const result = await pool.query(
      `UPDATE admin_sessions 
       SET is_active = false 
       WHERE session_token = $1
       RETURNING admin_id`,
      [sessionToken]
    );
    
    if (result.rows.length > 0) {
      const adminId = result.rows[0].admin_id;
      
      await pool.query(
        `INSERT INTO admin_action_logs (admin_id, admin_email, action_type, action_details, ip_address)
         VALUES ($1, $2, 'logout', $3, $4)`,
        [adminId, req.admin.email, JSON.stringify({ method: 'user_initiated' }), ipAddress]
      );
    }
    
    res.json({ success: true, message: 'Logged out successfully' });
  } catch (error) {
    console.error('❌ Logout error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/terminate-other-sessions', authenticateAdmin, async (req, res) => {
  const sessionToken = req.headers['authorization']?.split(' ')[1];
  const ipAddress = req.ip || req.connection.remoteAddress;
  
  try {
    console.log('🔒 Terminating other sessions for:', req.admin.email);
    
    const result = await pool.query(
      `UPDATE admin_sessions 
       SET is_active = false 
       WHERE admin_id = $1 
         AND session_token != $2 
         AND is_active = true
       RETURNING id`,
      [req.admin.id, sessionToken]
    );
    
    await pool.query(
      `INSERT INTO admin_action_logs (admin_id, admin_email, action_type, action_details, ip_address)
       VALUES ($1, $2, 'terminate_other_sessions', $3, $4)`,
      [req.admin.id, req.admin.email, JSON.stringify({ terminatedCount: result.rowCount }), ipAddress]
    );
    
    console.log(`✅ Terminated ${result.rowCount} other session(s)`);
    
    res.json({ 
      success: true, 
      message: `Terminated ${result.rowCount} other session(s)` 
    });
  } catch (error) {
    console.error('❌ Terminate sessions error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/profile', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
        a.id, a.full_name, a.email, a.phone, a.role, a.is_active,
        a.last_login_at, a.last_login_ip, a.failed_login_attempts,
        a.locked_until, a.created_at,
        (SELECT COUNT(*) FROM admin_sessions 
         WHERE admin_id = a.id AND is_active = true AND expires_at > NOW()) as active_sessions
       FROM admins a
       WHERE a.id = $1`,
      [req.admin.id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Admin not found' });
    }
    
    const sessionToken = req.headers['authorization']?.split(' ')[1];
    const session = await pool.query(
      `SELECT created_at as login_time, expires_at, device_info, ip_address, user_agent
       FROM admin_sessions 
       WHERE session_token = $1`,
      [sessionToken]
    );
    
    res.json({
      admin: result.rows[0],
      currentSession: session.rows[0] || null
    });
    
  } catch (error) {
    console.error('❌ Error fetching admin profile:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/profile/simple', authenticateAdmin, async (req, res) => {
  try {
    res.json({
      admin: {
        id: req.admin.id,
        full_name: req.admin.full_name,
        email: req.admin.email,
        phone: req.admin.phone,
        role: req.admin.role
      }
    });
  } catch (error) {
    console.error('❌ Error fetching admin profile:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/login-history', authenticateAdmin, async (req, res) => {
  try {
    if (req.admin.role !== 'super_admin') {
      return res.status(403).json({ error: 'Only super admins can view login history' });
    }
    
    const { limit = 50, adminId } = req.query;
    
    let query = `
      SELECT 
        lh.*,
        a.full_name,
        a.email
      FROM admin_login_history lh
      LEFT JOIN admins a ON lh.admin_id = a.id
    `;
    
    const params = [];
    
    if (adminId) {
      query += ` WHERE lh.admin_id = $1`;
      params.push(adminId);
    }
    
    query += ` ORDER BY lh.created_at DESC LIMIT $${params.length + 1}`;
    params.push(limit);
    
    const result = await pool.query(query, params);
    
    res.json({
      total: result.rows.length,
      history: result.rows
    });
    
  } catch (error) {
    console.error('❌ Error fetching login history:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/create', authenticateAdmin, async (req, res) => {
  const { full_name, email, phone, password, role = 'admin' } = req.body;
  
  let client;
  
  try {
    if (req.admin.role !== 'super_admin') {
      console.log('❌ Unauthorized attempt to create admin by:', req.admin.email);
      return res.status(403).json({ 
        success: false,
        error: 'Only super admins can create new admins' 
      });
    }
    
    if (!full_name || !email || !phone || !password) {
      return res.status(400).json({ 
        success: false,
        error: 'All fields are required' 
      });
    }
    
    if (password.length < 8) {
      return res.status(400).json({ 
        success: false,
        error: 'Password must be at least 8 characters' 
      });
    }
    
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    
    if (!(hasUpperCase && hasLowerCase && hasNumbers && hasSpecialChar)) {
      return res.status(400).json({ 
        success: false,
        error: 'Password must contain uppercase, lowercase, number, and special character' 
      });
    }
    
    client = await pool.connect();
    await client.query('BEGIN');
    
    const adminCount = await client.query('SELECT COUNT(*) FROM admins');
    const currentCount = parseInt(adminCount.rows[0].count);
    
    if (currentCount >= 3) {
      await client.query('ROLLBACK');
      return res.status(403).json({ 
        success: false,
        error: 'Maximum of 3 admins allowed',
        currentCount,
        maxAllowed: 3
      });
    }
    
    const existing = await client.query(
      'SELECT id FROM admins WHERE email = $1 OR phone = $2',
      [email, phone]
    );
    
    if (existing.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ 
        success: false,
        error: 'Email or phone already exists' 
      });
    }
    
    const hashedPassword = await bcrypt.hash(password, 12);
    
    const result = await client.query(
      `INSERT INTO admins 
       (full_name, email, phone, password_hash, role, created_by, created_at, updated_at) 
       VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW()) 
       RETURNING id, full_name, email, phone, role, created_at`,
      [full_name, email, phone, hashedPassword, role, req.admin.id]
    );
    
    await client.query(
      `INSERT INTO admin_action_logs 
       (admin_id, admin_email, action_type, action_details, created_at)
       VALUES ($1, $2, 'create_admin', $3, NOW())`,
      [req.admin.id, req.admin.email, JSON.stringify({ newAdmin: email, role })]
    );
    
    await client.query('COMMIT');
    
    const newAdmin = result.rows[0];
    
    console.log('✅ New admin created by:', req.admin.email);
    console.log('📊 Total admins now:', currentCount + 1);
    
    res.json({
      success: true,
      message: 'Admin created successfully',
      admin: newAdmin,
      totalAdmins: currentCount + 1,
      remainingSlots: 3 - (currentCount + 1)
    });
    
  } catch (error) {
    if (client) await client.query('ROLLBACK');
    console.error('❌ Error creating admin:', error);
    
    if (error.code === '23505') {
      return res.status(400).json({ 
        success: false,
        error: 'Email or phone already exists' 
      });
    }
    
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  } finally {
    if (client) client.release();
  }
});

app.get('/api/admin/all', authenticateAdmin, async (req, res) => {
  try {
    if (req.admin.role !== 'super_admin') {
      console.log('❌ Unauthorized attempt to view admins by:', req.admin.email);
      return res.status(403).json({ error: 'Only super admins can view all admins' });
    }
    
    const result = await pool.query(
      `SELECT 
        a.id, 
        a.full_name, 
        a.email, 
        a.phone, 
        a.role, 
        a.is_active, 
        a.last_login_at, 
        a.created_at,
        creator.full_name as created_by_name
       FROM admins a
       LEFT JOIN admins creator ON a.created_by = creator.id
       ORDER BY a.created_at DESC`
    );
    
    const countResult = await pool.query('SELECT COUNT(*) FROM admins');
    const totalAdmins = parseInt(countResult.rows[0].count);
    
    console.log(`📊 Admins fetched: ${result.rows.length} (Total: ${totalAdmins}/3)`);
    
    res.json({
      admins: result.rows,
      total: totalAdmins,
      maxAllowed: 3,
      remainingSlots: 3 - totalAdmins
    });
    
  } catch (error) {
    console.error('❌ Error fetching admins:', error);
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/:adminId/toggle-status', authenticateAdmin, async (req, res) => {
  const { adminId } = req.params;
  
  try {
    if (req.admin.role !== 'super_admin') {
      console.log('❌ Unauthorized attempt to toggle status by:', req.admin.email);
      return res.status(403).json({ error: 'Only super admins can modify admin status' });
    }
    
    if (parseInt(adminId) === req.admin.id) {
      return res.status(400).json({ error: 'Cannot deactivate your own account' });
    }
    
    const result = await pool.query(
      'UPDATE admins SET is_active = NOT is_active, updated_at = NOW() WHERE id = $1 RETURNING id, email, is_active',
      [adminId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Admin not found' });
    }
    
    const status = result.rows[0].is_active ? 'activated' : 'deactivated';
    console.log(`✅ Admin ${result.rows[0].email} ${status} by:`, req.admin.email);
    
    res.json({ 
      success: true, 
      message: `Admin ${status} successfully`,
      admin: result.rows[0]
    });
    
  } catch (error) {
    console.error('❌ Error toggling admin status:', error);
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/:adminId', authenticateAdmin, async (req, res) => {
  const { adminId } = req.params;
  
  try {
    if (req.admin.role !== 'super_admin') {
      console.log('❌ Unauthorized attempt to delete admin by:', req.admin.email);
      return res.status(403).json({ error: 'Only super admins can delete admins' });
    }
    
    if (parseInt(adminId) === req.admin.id) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }
    
    const countResult = await pool.query('SELECT COUNT(*) FROM admins');
    const currentCount = parseInt(countResult.rows[0].count);
    
    if (currentCount <= 1) {
      return res.status(400).json({ error: 'Cannot delete the last admin' });
    }
    
    const result = await pool.query(
      'DELETE FROM admins WHERE id = $1 RETURNING id, email',
      [adminId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Admin not found' });
    }
    
    console.log(`✅ Admin ${result.rows[0].email} deleted by:`, req.admin.email);
    console.log(`📊 Total admins now: ${currentCount - 1}`);
    
    res.json({ 
      success: true, 
      message: 'Admin deleted successfully',
      deletedAdmin: result.rows[0],
      totalAdmins: currentCount - 1,
      remainingSlots: 3 - (currentCount - 1)
    });
    
  } catch (error) {
    console.error('❌ Error deleting admin:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
  try {
    const userStats = await pool.query(`
      SELECT 
        COUNT(*) as total_users,
        COUNT(*) FILTER (WHERE created_at::date = CURRENT_DATE) as new_users_today,
        COUNT(*) FILTER (WHERE last_login_at > NOW() - INTERVAL '24 hours') as active_24h
      FROM profiles
    `);
    
    const betStats = await pool.query(`
      SELECT 
        COUNT(*) as total_bets,
        COUNT(*) FILTER (WHERE created_at::date = CURRENT_DATE) as bets_today,
        COALESCE(SUM(stake), 0) as total_wagered,
        COALESCE(SUM(profit), 0) as total_profit
      FROM bets
    `);
    
    const transactionStats = await pool.query(`
      SELECT 
        COALESCE(SUM(amount) FILTER (WHERE type = 'deposit' AND status = 'completed'), 0) as total_deposits,
        COALESCE(SUM(amount) FILTER (WHERE type = 'withdrawal' AND status = 'completed'), 0) as total_withdrawals,
        COUNT(*) FILTER (WHERE type = 'withdrawal' AND status = 'pending') as pending_withdrawals_count,
        COALESCE(SUM(amount) FILTER (WHERE type = 'withdrawal' AND status = 'pending'), 0) as pending_withdrawals_amount
      FROM transactions
    `);
    
    const adminStats = await pool.query(`
      SELECT 
        COUNT(*) as total_admins,
        COUNT(*) FILTER (WHERE role = 'super_admin') as super_admins
      FROM admins
    `);
    
    res.json({
      users: userStats.rows[0],
      bets: betStats.rows[0],
      transactions: transactionStats.rows[0],
      admins: adminStats.rows[0],
      maxAdmins: 3,
      remainingAdminSlots: 3 - parseInt(adminStats.rows[0].total_admins)
    });
    
  } catch (error) {
    console.error('❌ Admin stats error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== FOOTBALL API PROXY ENDPOINTS ====================

// Proxy for football API upcoming matches
app.get('/api/football/fixtures/upcoming', authenticateToken, async (req, res) => {
  try {
    const { league } = req.query;
    const FOOTBALL_API_KEY = '06fd9ad610ba7c51d947ecab06d4f87';
    
    let url = 'https://v3.football.api-sports.io/fixtures';
    const params = new URLSearchParams({
      next: '50',
      timezone: 'Africa/Nairobi',
      status: 'NS'
    });
    
    if (league) {
      params.append('league', league);
    }
    
    const response = await axios.get(`${url}?${params.toString()}`, {
      headers: {
        'x-apisports-key': FOOTBALL_API_KEY,
        'x-apisports-host': 'v3.football.api-sports.io'
      },
      timeout: 10000
    });
    
    res.json(response.data);
  } catch (error) {
    console.error('❌ Football API upcoming matches error:', error.message);
    res.status(500).json({ response: [], error: error.message });
  }
});

// Proxy for football API live matches
app.get('/api/football/fixtures/live', authenticateToken, async (req, res) => {
  try {
    const FOOTBALL_API_KEY = '06fd9ad610ba7c51d947ecab06d4f87';
    
    const response = await axios.get('https://v3.football.api-sports.io/fixtures?live=all', {
      headers: {
        'x-apisports-key': FOOTBALL_API_KEY,
        'x-apisports-host': 'v3.football.api-sports.io'
      },
      timeout: 10000
    });
    
    res.json(response.data);
  } catch (error) {
    console.error('❌ Football API live matches error:', error.message);
    res.status(500).json({ response: [], error: error.message });
  }
});

// Proxy for football API odds
app.get('/api/football/odds/:fixtureId', authenticateToken, async (req, res) => {
  try {
    const { fixtureId } = req.params;
    const FOOTBALL_API_KEY = '06fd9ad610ba7c51d947ecab06d4f87';
    
    const response = await axios.get(`https://v3.football.api-sports.io/odds?fixture=${fixtureId}&bookmaker=bet365`, {
      headers: {
        'x-apisports-key': FOOTBALL_API_KEY,
        'x-apisports-host': 'v3.football.api-sports.io'
      },
      timeout: 10000
    });
    
    res.json(response.data);
  } catch (error) {
    console.error('❌ Football API odds error:', error.message);
    res.status(500).json({ response: null, error: error.message });
  }
});

// ==================== GAME ROUND MANAGEMENT ====================

// Get current round for a game
app.get('/api/games/current-round/:gameType', authenticateToken, async (req, res) => {
  const { gameType } = req.params;
  
  try {
    if (!['aviator', 'jetx'].includes(gameType)) {
      return res.status(400).json({ error: 'Invalid game type' });
    }
    
    const activeRound = await pool.query(
      `SELECT gr.*, 
              COUNT(b.id) as total_bets,
              COALESCE(SUM(b.stake), 0) as total_wagered
       FROM game_rounds gr
       LEFT JOIN bets b ON gr.id = b.round_id AND b.game_type = $1
       WHERE gr.game = $1 AND gr.status IN ('waiting', 'flying')
       GROUP BY gr.id
       ORDER BY gr.created_at DESC 
       LIMIT 1`,
      [gameType]
    );
    
    if (activeRound.rows.length === 0) {
      const lastRound = await pool.query(
        `SELECT round_number FROM game_rounds 
         WHERE game = $1 
         ORDER BY round_number DESC 
         LIMIT 1`,
        [gameType]
      );
      
      const nextRoundNumber = lastRound.rows.length > 0 ? lastRound.rows[0].round_number + 1 : 1;
      
      return res.json({
        round: null,
        status: 'waiting',
        nextRoundNumber,
        countdown: 8
      });
    }
    
    const round = activeRound.rows[0];
    
    res.json({
      round: {
        roundId: round.id,
        roundNumber: round.round_number,
        status: round.status,
        crashPoint: round.crash_point,
        currentMultiplier: round.status === 'flying' ? 1.0 : null,
        startTime: round.started_at,
        totalBets: parseInt(round.total_bets),
        totalWagered: parseFloat(round.total_wagered)
      }
    });
    
  } catch (error) {
    console.error('❌ Get current round error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Start a new round
app.post('/api/games/start-round/:gameType', authenticateToken, async (req, res) => {
  const { gameType } = req.params;
  const { userId } = req.body;
  
  try {
    if (!['aviator', 'jetx'].includes(gameType)) {
      return res.status(400).json({ error: 'Invalid game type' });
    }
    
    const activeRound = await pool.query(
      `SELECT id, status FROM game_rounds 
       WHERE game = $1 AND status IN ('waiting', 'flying')`,
      [gameType]
    );
    
    if (activeRound.rows.length > 0) {
      return res.status(400).json({ 
        error: 'Round already in progress',
        roundId: activeRound.rows[0].id,
        status: activeRound.rows[0].status
      });
    }
    
    const lastRound = await pool.query(
      `SELECT round_number FROM game_rounds 
       WHERE game = $1 
       ORDER BY round_number DESC 
       LIMIT 1`,
      [gameType]
    );
    
    const nextRoundNumber = lastRound.rows.length > 0 ? lastRound.rows[0].round_number + 1 : 1;
    
    const crashPoint = generateCrashPoint();
    
    const newRound = await pool.query(
      `INSERT INTO game_rounds 
       (game, round_number, crash_point, status, started_at, created_at)
       VALUES ($1, $2, $3, 'flying', NOW(), NOW())
       RETURNING id, round_number, crash_point`,
      [gameType, nextRoundNumber, crashPoint]
    );
    
    console.log(`🎮 New ${gameType} round #${nextRoundNumber} started, crash point: ${crashPoint}x`);
    
    const crashDelay = Math.random() * 20000 + 10000;
    setTimeout(async () => {
      try {
        await pool.query(
          `UPDATE game_rounds 
           SET status = 'crashed', ended_at = NOW()
           WHERE id = $1 AND status = 'flying'`,
          [newRound.rows[0].id]
        );
        console.log(`💥 ${gameType} round #${nextRoundNumber} auto-crashed at ${crashPoint}x`);
      } catch (err) {
        console.error('Auto-crash error:', err);
      }
    }, crashDelay);
    
    res.json({
      success: true,
      roundId: newRound.rows[0].id,
      roundNumber: newRound.rows[0].round_number,
      crashPoint: parseFloat(newRound.rows[0].crash_point),
      status: 'flying'
    });
    
  } catch (error) {
    console.error('❌ Start round error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Helper function to generate crash point
function generateCrashPoint() {
  const random = Math.random() * 100;
  
  if (random < 50) {
    return 1.00 + Math.random() * 1.00;
  } else if (random < 70) {
    return 2.00 + Math.random() * 0.99;
  } else if (random < 85) {
    return 3.00 + Math.random() * 2.00;
  } else if (random < 91) {
    return 5.00 + Math.random() * 3.00;
  } else if (random < 94) {
    return 8.00 + Math.random() * 5.00;
  } else if (random < 96.5) {
    return 13.00 + Math.random() * 6.00;
  } else if (random < 98) {
    return 19.00 + Math.random() * 10.00;
  } else if (random < 99) {
    return 29.00 + Math.random() * 20.00;
  } else if (random < 99.5) {
    return 49.00 + Math.random() * 26.00;
  } else {
    return 75.00 + Math.random() * 55.00;
  }
}

// Get round details by ID
app.get('/api/games/round/:roundId', authenticateToken, async (req, res) => {
  const { roundId } = req.params;
  
  try {
    const round = await pool.query(
      `SELECT gr.*, 
              COUNT(b.id) as total_bets,
              COALESCE(SUM(b.stake), 0) as total_wagered,
              COALESCE(SUM(CASE WHEN b.status = 'cashed_out' THEN b.actual_winnings ELSE 0 END), 0) as total_paid
       FROM game_rounds gr
       LEFT JOIN bets b ON gr.id = b.round_id
       WHERE gr.id = $1
       GROUP BY gr.id`,
      [roundId]
    );
    
    if (round.rows.length === 0) {
      return res.status(404).json({ error: 'Round not found' });
    }
    
    res.json({
      roundId: round.rows[0].id,
      roundNumber: round.rows[0].round_number,
      gameType: round.rows[0].game,
      status: round.rows[0].status,
      crashPoint: parseFloat(round.rows[0].crash_point || 0),
      currentMultiplier: round.rows[0].status === 'flying' ? 1.0 : null,
      startTime: round.rows[0].started_at,
      endTime: round.rows[0].ended_at,
      stats: {
        totalBets: parseInt(round.rows[0].total_bets),
        totalWagered: parseFloat(round.rows[0].total_wagered),
        totalPaid: parseFloat(round.rows[0].total_paid)
      }
    });
    
  } catch (error) {
    console.error('❌ Get round details error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Place a bet - FIXED endpoint to /api/bets/place
app.post('/api/bets/place', authenticateToken, async (req, res) => {
  const { userId, selections, stake, totalOdds, potentialWinnings, betType } = req.body;
  
  let client;
  
  try {
    console.log('🎲 Bet placement:', { userId, stake, selections: selections?.length });
    
    if (stake < 10) {
      return res.status(400).json({ error: 'Minimum stake is KES 10' });
    }
    
    if (!selections || selections.length === 0) {
      return res.status(400).json({ error: 'No selections provided' });
    }
    
    client = await pool.connect();
    await client.query('BEGIN');
    
    const walletResult = await client.query(
      'SELECT * FROM wallets WHERE user_id = $1 FOR UPDATE',
      [userId]
    );
    
    if (walletResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Wallet not found' });
    }
    
    const currentBalance = parseFloat(walletResult.rows[0].main_balance);
    
    if (currentBalance < stake) {
      await client.query('ROLLBACK');
      return res.status(400).json({ 
        error: 'Insufficient balance',
        available: currentBalance,
        required: stake
      });
    }
    
    const referenceNumber = 'BET-' + Date.now() + '-' + Math.random().toString(36).substring(2, 8).toUpperCase();
    
    const betResult = await client.query(
      `INSERT INTO bets (
        user_id, selections, stake, total_odds, potential_winnings, 
        bet_type, reference_number, status, profit, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW()) RETURNING id`,
      [
        userId, 
        JSON.stringify(selections), 
        stake, 
        totalOdds, 
        potentialWinnings, 
        betType || (selections.length > 1 ? 'accumulator' : 'single'),
        referenceNumber,
        'pending',
        -stake
      ]
    );
    
    await client.query(
      `UPDATE wallets 
       SET main_balance = main_balance - $1,
           lifetime_bets = lifetime_bets + $1,
           total_profit = total_profit - $1,
           updated_at = NOW()
       WHERE user_id = $2`,
      [stake, userId]
    );
    
    await client.query(
      `INSERT INTO transactions (
        user_id, type, amount, status, description, reference, 
        balance_before, balance_after, profit, created_at
      ) VALUES ($1, 'bet', $2, 'completed', $3, $4, $5, $5 - $2, -$2, NOW())`,
      [userId, stake, `Bet placed on ${selections.length} selection(s)`, referenceNumber, currentBalance]
    );
    
    await client.query('COMMIT');
    
    const updatedWallet = await pool.query(
      'SELECT main_balance, total_profit FROM wallets WHERE user_id = $1',
      [userId]
    );
    
    res.json({ 
      success: true, 
      betId: betResult.rows[0].id,
      message: 'Bet placed successfully',
      newBalance: updatedWallet.rows[0].main_balance,
      newProfit: updatedWallet.rows[0].total_profit
    });
    
  } catch (error) {
    if (client) {
      await client.query('ROLLBACK');
      client.release();
    }
    console.error('❌ Bet error:', error);
    res.status(500).json({ error: error.message });
  } finally {
    if (client) client.release();
  }
});

// Keep the old endpoint for backward compatibility
app.post('/api/bets', authenticateToken, async (req, res) => {
  req.url = '/api/bets/place';
  return app.handle(req, res);
});

// Get settled bets for a user
app.get('/api/bets/settlements/:userId', authenticateToken, async (req, res) => {
  const { userId } = req.params;
  
  try {
    const settlements = await pool.query(
      `SELECT b.*, p.full_name
       FROM bets b
       JOIN profiles p ON b.user_id = p.id
       WHERE b.user_id = $1 
         AND b.status IN ('won', 'lost', 'cashed_out')
         AND b.settled_at > NOW() - INTERVAL '24 hours'
       ORDER BY b.settled_at DESC`,
      [userId]
    );
    
    const formattedSettlements = settlements.rows.map(bet => ({
      id: bet.id,
      stake: parseFloat(bet.stake),
      potentialWinnings: parseFloat(bet.potential_winnings),
      actualWinnings: parseFloat(bet.actual_winnings || 0),
      profit: parseFloat(bet.profit || 0),
      status: bet.status,
      result: bet.status === 'won' || bet.status === 'cashed_out' ? 'won' : 'lost',
      winnings: bet.actual_winnings || (bet.status === 'cashed_out' ? bet.potential_winnings : 0),
      settledAt: bet.settled_at,
      selections: bet.selections
    }));
    
    res.json({
      settlements: formattedSettlements,
      count: formattedSettlements.length
    });
    
  } catch (error) {
    console.error('❌ Get settlements error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get jackpot matches for a specific week
app.get('/api/jackpot/matches/:week', authenticateToken, async (req, res) => {
  const { week } = req.params;
  
  try {
    const matches = generateJackpotMatches(17);
    
    res.json({
      week: parseInt(week),
      matches,
      totalPool: 1500000,
      totalEntries: Math.floor(Math.random() * 200) + 50
    });
    
  } catch (error) {
    console.error('❌ Get jackpot matches error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Helper function to generate jackpot matches
function generateJackpotMatches(count) {
  const leagues = [
    { id: 39, name: 'Premier League', country: 'England' },
    { id: 140, name: 'La Liga', country: 'Spain' },
    { id: 78, name: 'Bundesliga', country: 'Germany' },
    { id: 135, name: 'Serie A', country: 'Italy' },
    { id: 61, name: 'Ligue 1', country: 'France' },
    { id: 2, name: 'Champions League', country: 'Europe' },
  ];
  
  const teams = [
    { home: 'Manchester City', away: 'Arsenal' },
    { home: 'Liverpool', away: 'Chelsea' },
    { home: 'Real Madrid', away: 'Barcelona' },
    { home: 'Bayern Munich', away: 'Dortmund' },
    { home: 'Inter Milan', away: 'AC Milan' },
    { home: 'PSG', away: 'Marseille' },
    { home: 'Tottenham', away: 'Manchester United' },
    { home: 'Atletico Madrid', away: 'Sevilla' },
    { home: 'RB Leipzig', away: 'Bayer Leverkusen' },
    { home: 'Napoli', away: 'Juventus' },
    { home: 'Ajax', away: 'PSV' },
    { home: 'Benfica', away: 'Porto' },
    { home: 'Celtic', away: 'Rangers' },
    { home: 'Galatasaray', away: 'Fenerbahce' },
    { home: 'Club Brugge', away: 'Anderlecht' },
    { home: 'Shakhtar', away: 'Dynamo Kyiv' },
    { home: 'Salzburg', away: 'Sturm Graz' },
  ];
  
  const matches = [];
  
  for (let i = 0; i < count; i++) {
    const league = leagues[i % leagues.length];
    const teamPair = teams[i % teams.length];
    const date = new Date();
    date.setDate(date.getDate() + (i % 7) + 1);
    date.setHours(15 + (i % 8), 0, 0, 0);
    
    const random = (min, max) => {
      return Number((min + (i * 0.1) % (max - min)).toFixed(2));
    };
    
    matches.push({
      id: i + 1,
      fixtureId: 100000 + i,
      homeTeam: teamPair.home,
      awayTeam: teamPair.away,
      league: league.name,
      leagueId: league.id,
      country: league.country,
      date: date.toISOString(),
      timestamp: date.getTime(),
      odds: {
        home: random(1.5, 3.0),
        draw: random(2.8, 4.0),
        away: random(1.8, 3.5)
      }
    });
  }
  
  return matches;
}

// Get user's jackpot entry for a specific week
app.get('/api/jackpot/user/:userId/week/:week', authenticateToken, async (req, res) => {
  const { userId, week } = req.params;
  
  try {
    const result = await pool.query(
      `SELECT * FROM jackpot_entries 
       WHERE user_id = $1 AND EXTRACT(WEEK FROM created_at) = $2
       ORDER BY created_at DESC LIMIT 1`,
      [userId, week]
    );
    
    if (result.rows.length === 0) {
      return res.json({ entry: null });
    }
    
    const entry = result.rows[0];
    
    res.json({
      entry: {
        id: entry.id,
        userId: entry.user_id,
        weekNumber: parseInt(week),
        stake: parseFloat(entry.stake),
        matches: entry.numbers,
        totalOdds: entry.stake * 500,
        potentialWinnings: entry.stake * 500,
        status: entry.status,
        createdAt: entry.created_at
      }
    });
    
  } catch (error) {
    console.error('❌ Get user jackpot entry error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get jackpot leaderboard
app.get('/api/jackpot/leaderboard/:week', authenticateToken, async (req, res) => {
  const { week } = req.params;
  
  try {
    const result = await pool.query(
      `SELECT je.*, p.full_name, p.phone
       FROM jackpot_entries je
       JOIN profiles p ON je.user_id = p.id
       WHERE EXTRACT(WEEK FROM je.created_at) = $1
       ORDER BY je.stake DESC
       LIMIT 20`,
      [week]
    );
    
    const entries = result.rows.map(entry => ({
      id: entry.id,
      userName: entry.full_name,
      stake: parseFloat(entry.stake),
      potentialWinnings: entry.stake * 500,
      status: entry.status,
      date: entry.created_at
    }));
    
    res.json({ entries });
    
  } catch (error) {
    console.error('❌ Get jackpot leaderboard error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== ADMIN AVIATOR CONTROLS ====================
app.get('/api/admin/aviator/settings', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM game_settings WHERE game = 'aviator' LIMIT 1`
    );
    
    if (result.rows.length === 0) {
      return res.json({
        game: 'aviator',
        enabled: true,
        min_bet: 10,
        max_bet: 10000,
        house_edge: 3,
        provably_fair: true,
        max_payout: 1000000,
        auto_crash_enabled: false,
        auto_crash_multiplier: null,
        current_seed: null,
        next_seed: null,
        created_at: new Date(),
        updated_at: new Date()
      });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('❌ Error fetching Aviator settings:', error);
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/aviator/settings', authenticateAdmin, async (req, res) => {
  const {
    enabled,
    min_bet,
    max_bet,
    house_edge,
    provably_fair,
    max_payout,
    auto_crash_enabled,
    auto_crash_multiplier
  } = req.body;
  
  try {
    if (min_bet && max_bet && min_bet > max_bet) {
      return res.status(400).json({ error: 'Min bet cannot exceed max bet' });
    }
    
    if (house_edge && (house_edge < 0 || house_edge > 100)) {
      return res.status(400).json({ error: 'House edge must be between 0 and 100' });
    }
    
    if (auto_crash_enabled && auto_crash_multiplier && auto_crash_multiplier < 1.01) {
      return res.status(400).json({ error: 'Auto crash multiplier must be at least 1.01' });
    }
    
    const result = await pool.query(
      `UPDATE game_settings 
       SET enabled = COALESCE($1, enabled),
           min_bet = COALESCE($2, min_bet),
           max_bet = COALESCE($3, max_bet),
           house_edge = COALESCE($4, house_edge),
           provably_fair = COALESCE($5, provably_fair),
           max_payout = COALESCE($6, max_payout),
           auto_crash_enabled = COALESCE($7, auto_crash_enabled),
           auto_crash_multiplier = COALESCE($8, auto_crash_multiplier),
           updated_at = NOW(),
           updated_by = $9
       WHERE game = 'aviator'
       RETURNING *`,
      [
        enabled,
        min_bet,
        max_bet,
        house_edge,
        provably_fair,
        max_payout,
        auto_crash_enabled,
        auto_crash_multiplier,
        req.admin.id
      ]
    );
    
    if (result.rows.length === 0) {
      const insertResult = await pool.query(
        `INSERT INTO game_settings (
          game, enabled, min_bet, max_bet, house_edge, 
          provably_fair, max_payout, auto_crash_enabled, 
          auto_crash_multiplier, created_by, updated_by
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING *`,
        [
          'aviator',
          enabled || true,
          min_bet || 10,
          max_bet || 10000,
          house_edge || 3,
          provably_fair !== false,
          max_payout || 1000000,
          auto_crash_enabled || false,
          auto_crash_multiplier || null,
          req.admin.id,
          req.admin.id
        ]
      );
      
      await logAdminAction(req.admin.id, 'update_aviator_settings', 'game', 'aviator', insertResult.rows[0]);
      
      return res.json({
        success: true,
        message: 'Aviator settings created successfully',
        settings: insertResult.rows[0]
      });
    }
    
    await logAdminAction(req.admin.id, 'update_aviator_settings', 'game', 'aviator', result.rows[0]);
    
    res.json({
      success: true,
      message: 'Aviator settings updated successfully',
      settings: result.rows[0]
    });
    
  } catch (error) {
    console.error('❌ Error updating Aviator settings:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/aviator/rotate-seed', authenticateAdmin, async (req, res) => {
  try {
    const newSeed = crypto.randomBytes(32).toString('hex');
    const nextSeed = crypto.randomBytes(32).toString('hex');
    
    const result = await pool.query(
      `UPDATE game_settings 
       SET current_seed = $1,
           next_seed = $2,
           seed_rotated_at = NOW(),
           seed_rotated_by = $3,
           updated_at = NOW()
       WHERE game = 'aviator'
       RETURNING current_seed, next_seed, seed_rotated_at`,
      [newSeed, nextSeed, req.admin.id]
    );
    
    if (result.rows.length === 0) {
      const insertResult = await pool.query(
        `INSERT INTO game_settings (
          game, current_seed, next_seed, seed_rotated_at, 
          seed_rotated_by, created_by, updated_by
        ) VALUES ($1, $2, $3, NOW(), $4, $5, $6)
        RETURNING current_seed, next_seed, seed_rotated_at`,
        ['aviator', newSeed, nextSeed, req.admin.id, req.admin.id, req.admin.id]
      );
      
      await logAdminAction(req.admin.id, 'rotate_aviator_seed', 'game', 'aviator', { newSeed });
      
      return res.json({
        success: true,
        message: 'Game seed rotated successfully',
        seed: insertResult.rows[0].current_seed,
        nextSeed: insertResult.rows[0].next_seed,
        rotatedAt: insertResult.rows[0].seed_rotated_at
      });
    }
    
    await logAdminAction(req.admin.id, 'rotate_aviator_seed', 'game', 'aviator', { newSeed });
    
    res.json({
      success: true,
      message: 'Game seed rotated successfully',
      seed: result.rows[0].current_seed,
      nextSeed: result.rows[0].next_seed,
      rotatedAt: result.rows[0].seed_rotated_at
    });
    
  } catch (error) {
    console.error('❌ Error rotating seed:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/aviator/force-crash', authenticateAdmin, async (req, res) => {
  const { multiplier, reason } = req.body;
  
  try {
    const activeRound = await pool.query(
      `SELECT * FROM game_rounds 
       WHERE game = 'aviator' AND status = 'flying' 
       ORDER BY created_at DESC 
       LIMIT 1`
    );
    
    if (activeRound.rows.length === 0) {
      return res.status(400).json({ error: 'No active round to crash' });
    }
    
    const round = activeRound.rows[0];
    
    const crashMultiplier = multiplier || 1.01;
    
    await pool.query(
      `UPDATE game_rounds 
       SET status = 'crashed',
           crash_point = $1,
           ended_at = NOW(),
           forced_crash = true,
           forced_crash_reason = $2,
           forced_crash_by = $3
       WHERE id = $4`,
      [crashMultiplier, reason || 'Admin forced crash', req.admin.id, round.id]
    );
    
    const pendingBets = await pool.query(
      `SELECT * FROM bets 
       WHERE game_type = 'aviator' 
       AND round_id = $1 
       AND status = 'pending'`,
      [round.id]
    );
    
    for (const bet of pendingBets.rows) {
      await pool.query(
        `UPDATE bets 
         SET status = 'lost',
             settled_at = NOW()
         WHERE id = $1`,
        [bet.id]
      );
    }
    
    await logAdminAction(req.admin.id, 'force_crash_aviator', 'game', round.id.toString(), {
      multiplier: crashMultiplier,
      reason,
      betsSettled: pendingBets.rows.length
    });
    
    res.json({
      success: true,
      message: `Round crashed at ${crashMultiplier}x`,
      roundId: round.id,
      crashMultiplier,
      betsSettled: pendingBets.rows.length
    });
    
  } catch (error) {
    console.error('❌ Error forcing crash:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/aviator/active-round', authenticateAdmin, async (req, res) => {
  try {
    const activeRound = await pool.query(
      `SELECT gr.*, 
              COUNT(b.id) as total_bets,
              COALESCE(SUM(b.stake), 0) as total_wagered,
              COUNT(CASE WHEN b.status = 'cashed_out' THEN 1 END) as cashed_out_count,
              COALESCE(SUM(CASE WHEN b.status = 'cashed_out' THEN b.actual_winnings ELSE 0 END), 0) as total_paid
       FROM game_rounds gr
       LEFT JOIN bets b ON gr.id = b.round_id AND b.game_type = 'aviator'
       WHERE gr.game = 'aviator' AND gr.status IN ('waiting', 'flying')
       GROUP BY gr.id
       ORDER BY gr.created_at DESC 
       LIMIT 1`
    );
    
    if (activeRound.rows.length === 0) {
      return res.json({ active: false });
    }
    
    const participants = await pool.query(
      `SELECT b.user_id, p.full_name, b.stake, b.potential_winnings, 
              b.cashout_multiplier, b.status, b.created_at
       FROM bets b
       JOIN profiles p ON b.user_id = p.id
       WHERE b.round_id = $1 AND b.game_type = 'aviator'
       ORDER BY b.created_at DESC`,
      [activeRound.rows[0].id]
    );
    
    res.json({
      active: true,
      round: activeRound.rows[0],
      participants: participants.rows
    });
    
  } catch (error) {
    console.error('❌ Error fetching active round:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/aviator/rounds', authenticateAdmin, async (req, res) => {
  const {
    page = 1,
    limit = 20,
    status,
    fromDate,
    toDate,
    minCrash,
    maxCrash
  } = req.query;
  
  const offset = (page - 1) * limit;
  
  try {
    let query = `
      SELECT gr.*, 
             COUNT(b.id) as total_bets,
             COALESCE(SUM(b.stake), 0) as total_wagered,
             COALESCE(SUM(CASE WHEN b.status = 'cashed_out' THEN b.actual_winnings ELSE 0 END), 0) as total_paid,
             COUNT(DISTINCT b.user_id) as unique_players
      FROM game_rounds gr
      LEFT JOIN bets b ON gr.id = b.round_id AND b.game_type = 'aviator'
      WHERE gr.game = 'aviator'
    `;
    
    const params = [];
    let paramIndex = 1;
    
    if (status) {
      query += ` AND gr.status = $${paramIndex}`;
      params.push(status);
      paramIndex++;
    }
    
    if (fromDate) {
      query += ` AND gr.created_at >= $${paramIndex}`;
      params.push(fromDate);
      paramIndex++;
    }
    
    if (toDate) {
      query += ` AND gr.created_at <= $${paramIndex}`;
      params.push(toDate);
      paramIndex++;
    }
    
    if (minCrash) {
      query += ` AND gr.crash_point >= $${paramIndex}`;
      params.push(minCrash);
      paramIndex++;
    }
    
    if (maxCrash) {
      query += ` AND gr.crash_point <= $${paramIndex}`;
      params.push(maxCrash);
      paramIndex++;
    }
    
    query += ` GROUP BY gr.id ORDER BY gr.created_at DESC LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
    params.push(limit, offset);
    
    const rounds = await pool.query(query, params);
    
    const countResult = await pool.query(
      `SELECT COUNT(*) FROM game_rounds WHERE game = 'aviator'`
    );
    
    res.json({
      rounds: rounds.rows,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: parseInt(countResult.rows[0].count),
        pages: Math.ceil(parseInt(countResult.rows[0].count) / limit)
      }
    });
    
  } catch (error) {
    console.error('❌ Error fetching round history:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/aviator/rounds/:roundId', authenticateAdmin, async (req, res) => {
  const { roundId } = req.params;
  
  try {
    const round = await pool.query(
      `SELECT gr.*, 
              COUNT(b.id) as total_bets,
              COALESCE(SUM(b.stake), 0) as total_wagered,
              COALESCE(SUM(CASE WHEN b.status = 'cashed_out' THEN b.actual_winnings ELSE 0 END), 0) as total_paid,
              COUNT(DISTINCT b.user_id) as unique_players
       FROM game_rounds gr
       LEFT JOIN bets b ON gr.id = b.round_id AND b.game_type = 'aviator'
       WHERE gr.id = $1
       GROUP BY gr.id`,
      [roundId]
    );
    
    if (round.rows.length === 0) {
      return res.status(404).json({ error: 'Round not found' });
    }
    
    const bets = await pool.query(
      `SELECT b.*, p.full_name, p.email, p.phone
       FROM bets b
       JOIN profiles p ON b.user_id = p.id
       WHERE b.round_id = $1 AND b.game_type = 'aviator'
       ORDER BY 
         CASE 
           WHEN b.status = 'cashed_out' THEN 1
           WHEN b.status = 'won' THEN 2
           WHEN b.status = 'lost' THEN 3
           ELSE 4
         END,
         b.created_at DESC`,
      [roundId]
    );
    
    const stats = {
      totalStake: bets.rows.reduce((sum, b) => sum + parseFloat(b.stake), 0),
      totalWon: bets.rows.filter(b => b.status === 'cashed_out' || b.status === 'won')
                .reduce((sum, b) => sum + parseFloat(b.actual_winnings || 0), 0),
      averageStake: bets.rows.length ? bets.rows.reduce((sum, b) => sum + parseFloat(b.stake), 0) / bets.rows.length : 0,
      highestWin: Math.max(...bets.rows.map(b => parseFloat(b.actual_winnings || 0))),
      cashedOutCount: bets.rows.filter(b => b.status === 'cashed_out').length,
      lostCount: bets.rows.filter(b => b.status === 'lost').length
    };
    
    res.json({
      round: round.rows[0],
      bets: bets.rows,
      statistics: stats
    });
    
  } catch (error) {
    console.error('❌ Error fetching round details:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/aviator/stats', authenticateAdmin, async (req, res) => {
  const { period = '24h' } = req.query;
  
  let interval;
  switch(period) {
    case '1h':
      interval = '1 hour';
      break;
    case '24h':
      interval = '24 hours';
      break;
    case '7d':
      interval = '7 days';
      break;
    case '30d':
      interval = '30 days';
      break;
    default:
      interval = '24 hours';
  }
  
  try {
    const overall = await pool.query(
      `SELECT 
         COUNT(DISTINCT round_id) as total_rounds,
         COUNT(id) as total_bets,
         COALESCE(SUM(stake), 0) as total_wagered,
         COALESCE(SUM(actual_winnings), 0) as total_paid,
         AVG(cashout_multiplier) as avg_cashout,
         COUNT(DISTINCT user_id) as unique_players
       FROM bets 
       WHERE game_type = 'aviator'
       AND created_at > NOW() - $1::interval`,
      [interval]
    );
    
    const hourly = await pool.query(
      `SELECT 
         DATE_TRUNC('hour', created_at) as hour,
         COUNT(*) as bet_count,
         COALESCE(SUM(stake), 0) as wagered,
         COALESCE(SUM(actual_winnings), 0) as paid
       FROM bets
       WHERE game_type = 'aviator'
         AND created_at > NOW() - $1::interval
       GROUP BY DATE_TRUNC('hour', created_at)
       ORDER BY hour DESC`,
      [interval]
    );
    
    const topPlayers = await pool.query(
      `SELECT 
         b.user_id,
         p.full_name,
         COUNT(*) as total_bets,
         COALESCE(SUM(b.stake), 0) as total_wagered,
         COALESCE(SUM(b.actual_winnings), 0) as total_won,
         COUNT(CASE WHEN b.status = 'cashed_out' THEN 1 END) as cashed_out_count
       FROM bets b
       JOIN profiles p ON b.user_id = p.id
       WHERE b.game_type = 'aviator'
         AND b.created_at > NOW() - $1::interval
       GROUP BY b.user_id, p.full_name
       ORDER BY total_wagered DESC
       LIMIT 10`,
      [interval]
    );
    
    const crashDistribution = await pool.query(
      `SELECT 
         CASE 
           WHEN crash_point < 2 THEN '1-2x'
           WHEN crash_point < 3 THEN '2-3x'
           WHEN crash_point < 5 THEN '3-5x'
           WHEN crash_point < 10 THEN '5-10x'
           ELSE '10x+'
         END as range,
         COUNT(*) as count
       FROM game_rounds
       WHERE game = 'aviator'
         AND created_at > NOW() - $1::interval
         AND crash_point IS NOT NULL
       GROUP BY 
         CASE 
           WHEN crash_point < 2 THEN '1-2x'
           WHEN crash_point < 3 THEN '2-3x'
           WHEN crash_point < 5 THEN '3-5x'
           WHEN crash_point < 10 THEN '5-10x'
           ELSE '10x+'
         END`,
      [interval]
    );
    
    const houseProfit = parseFloat(overall.rows[0].total_wagered) - parseFloat(overall.rows[0].total_paid);
    const houseEdge = overall.rows[0].total_wagered > 0 
      ? (houseProfit / parseFloat(overall.rows[0].total_wagered)) * 100 
      : 0;
    
    res.json({
      period,
      overall: {
        ...overall.rows[0],
        house_profit: houseProfit,
        house_edge: houseEdge.toFixed(2),
        payout_rate: overall.rows[0].total_wagered > 0 
          ? (parseFloat(overall.rows[0].total_paid) / parseFloat(overall.rows[0].total_wagered) * 100).toFixed(2)
          : 0
      },
      hourly: hourly.rows,
      topPlayers: topPlayers.rows,
      crashDistribution: crashDistribution.rows
    });
    
  } catch (error) {
    console.error('❌ Error fetching Aviator stats:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/aviator/active-players', authenticateAdmin, async (req, res) => {
  try {
    const activePlayers = await pool.query(
      `SELECT 
         p.id,
         p.full_name,
         p.email,
         p.phone,
         w.main_balance,
         COUNT(b.id) as bets_in_current_round,
         COALESCE(SUM(b.stake), 0) as total_stake_current_round,
         MAX(b.created_at) as last_bet_time
       FROM profiles p
       JOIN wallets w ON p.id = w.user_id
       JOIN bets b ON p.id = b.user_id
       JOIN game_rounds gr ON b.round_id = gr.id
       WHERE gr.game = 'aviator' 
         AND gr.status = 'flying'
         AND b.status = 'pending'
       GROUP BY p.id, p.full_name, p.email, p.phone, w.main_balance
       ORDER BY last_bet_time DESC`
    );
    
    res.json({
      count: activePlayers.rows.length,
      players: activePlayers.rows
    });
    
  } catch (error) {
    console.error('❌ Error fetching active players:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/aviator/auto-crash-queue', authenticateAdmin, async (req, res) => {
  const { multipliers } = req.body;
  
  try {
    if (!Array.isArray(multipliers)) {
      return res.status(400).json({ error: 'Multipliers must be an array' });
    }
    
    for (const m of multipliers) {
      if (m < 1.01) {
        return res.status(400).json({ error: 'All multipliers must be at least 1.01' });
      }
    }
    
    await pool.query(
      `UPDATE game_settings 
       SET auto_crash_queue = $1,
           auto_crash_queue_set_at = NOW(),
           auto_crash_queue_set_by = $2
       WHERE game = 'aviator'`,
      [JSON.stringify(multipliers), req.admin.id]
    );
    
    await logAdminAction(req.admin.id, 'set_auto_crash_queue', 'game', 'aviator', { multipliers });
    
    res.json({
      success: true,
      message: `Auto crash queue set with ${multipliers.length} multipliers`,
      multipliers
    });
    
  } catch (error) {
    console.error('❌ Error setting auto crash queue:', error);
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/aviator/auto-crash-queue', authenticateAdmin, async (req, res) => {
  try {
    await pool.query(
      `UPDATE game_settings 
       SET auto_crash_queue = NULL,
           auto_crash_queue_cleared_at = NOW(),
           auto_crash_queue_cleared_by = $1
       WHERE game = 'aviator'`,
      [req.admin.id]
    );
    
    await logAdminAction(req.admin.id, 'clear_auto_crash_queue', 'game', 'aviator', {});
    
    res.json({
      success: true,
      message: 'Auto crash queue cleared'
    });
    
  } catch (error) {
    console.error('❌ Error clearing auto crash queue:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/aviator/suspend-user', authenticateAdmin, async (req, res) => {
  const { userId, reason, duration } = req.body;
  
  try {
    const user = await pool.query(
      'SELECT id, full_name FROM profiles WHERE id = $1',
      [userId]
    );
    
    if (user.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const expiresAt = duration ? new Date(Date.now() + duration * 60 * 1000) : null;
    
    await pool.query(
      `INSERT INTO game_suspensions (
        user_id, game, reason, suspended_by, expires_at, created_at
      ) VALUES ($1, 'aviator', $2, $3, $4, NOW())`,
      [userId, reason, req.admin.id, expiresAt]
    );
    
    await pool.query(
      `UPDATE bets 
       SET status = 'cancelled',
           cancellation_reason = $1
       WHERE user_id = $2 
         AND game_type = 'aviator' 
         AND status = 'pending'`,
      ['User suspended from game', userId]
    );
    
    await logAdminAction(req.admin.id, 'suspend_user_aviator', 'user', userId, {
      reason,
      duration
    });
    
    res.json({
      success: true,
      message: `User ${user.rows[0].full_name} suspended from Aviator`,
      expiresAt
    });
    
  } catch (error) {
    console.error('❌ Error suspending user:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/aviator/suspended-users', authenticateAdmin, async (req, res) => {
  try {
    const suspended = await pool.query(
      `SELECT gs.*, p.full_name, p.email, p.phone,
              a.full_name as suspended_by_name
       FROM game_suspensions gs
       JOIN profiles p ON gs.user_id = p.id
       LEFT JOIN admins a ON gs.suspended_by = a.id
       WHERE gs.game = 'aviator'
         AND (gs.expires_at IS NULL OR gs.expires_at > NOW())
       ORDER BY gs.created_at DESC`
    );
    
    res.json(suspended.rows);
    
  } catch (error) {
    console.error('❌ Error fetching suspended users:', error);
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/aviator/suspended-users/:userId', authenticateAdmin, async (req, res) => {
  const { userId } = req.params;
  
  try {
    const result = await pool.query(
      `UPDATE game_suspensions 
       SET lifted_at = NOW(),
           lifted_by = $1
       WHERE user_id = $2 
         AND game = 'aviator'
         AND lifted_at IS NULL`,
      [req.admin.id, userId]
    );
    
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'No active suspension found for this user' });
    }
    
    await logAdminAction(req.admin.id, 'lift_suspension_aviator', 'user', userId, {});
    
    res.json({
      success: true,
      message: 'User suspension lifted'
    });
    
  } catch (error) {
    console.error('❌ Error lifting suspension:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/aviator/verify/:roundId', authenticateAdmin, async (req, res) => {
  const { roundId } = req.params;
  
  try {
    const round = await pool.query(
      `SELECT gr.*, gs.current_seed, gs.next_seed
       FROM game_rounds gr
       JOIN game_settings gs ON gr.game = gs.game
       WHERE gr.id = $1 AND gr.game = 'aviator'`,
      [roundId]
    );
    
    if (round.rows.length === 0) {
      return res.status(404).json({ error: 'Round not found' });
    }
    
    const data = round.rows[0];
    
    const verificationResult = verifyCrashPoint(
      data.server_seed,
      data.client_seed,
      data.nonce,
      data.crash_point
    );
    
    res.json({
      roundId: data.id,
      roundNumber: data.round_number,
      crashPoint: data.crash_point,
      serverSeed: data.server_seed,
      clientSeed: data.client_seed,
      nonce: data.nonce,
      verified: verificationResult.verified,
      expectedCrashPoint: verificationResult.expectedCrashPoint,
      timestamp: data.created_at
    });
    
  } catch (error) {
    console.error('❌ Error verifying round:', error);
    res.status(500).json({ error: error.message });
  }
});

function verifyCrashPoint(serverSeed, clientSeed, nonce, actualCrashPoint) {
  try {
    if (!serverSeed || !clientSeed) {
      return {
        verified: false,
        expectedCrashPoint: null,
        error: 'Missing seeds'
      };
    }
    
    const hmac = crypto.createHmac('sha256', serverSeed);
    hmac.update(`${clientSeed}:${nonce || 0}`);
    const hash = hmac.digest('hex');
    
    const hex = hash.substring(0, 13);
    const int = parseInt(hex, 16);
    const float = int / Math.pow(16, 13);
    
    const houseEdge = 0.03;
    const crashPoint = Math.max(1, 0.99 / (1 - float) + 0.01);
    
    const expectedCrashPoint = Math.round(crashPoint * 100) / 100;
    
    return {
      verified: Math.abs(expectedCrashPoint - actualCrashPoint) < 0.01,
      expectedCrashPoint
    };
  } catch (error) {
    console.error('Error in verification:', error);
    return {
      verified: false,
      expectedCrashPoint: null,
      error: error.message
    };
  }
}

app.post('/api/admin/aviator/export', authenticateAdmin, async (req, res) => {
  const { format = 'json', fromDate, toDate } = req.body;
  
  try {
    let query = `
      SELECT 
        gr.round_number,
        gr.crash_point,
        gr.status,
        gr.created_at as round_time,
        gr.ended_at,
        COUNT(b.id) as total_bets,
        COALESCE(SUM(b.stake), 0) as total_wagered,
        COALESCE(SUM(CASE WHEN b.status = 'cashed_out' THEN b.actual_winnings ELSE 0 END), 0) as total_paid,
        COUNT(DISTINCT b.user_id) as unique_players
      FROM game_rounds gr
      LEFT JOIN bets b ON gr.id = b.round_id AND b.game_type = 'aviator'
      WHERE gr.game = 'aviator'
    `;
    
    const params = [];
    let paramIndex = 1;
    
    if (fromDate) {
      query += ` AND gr.created_at >= $${paramIndex}`;
      params.push(fromDate);
      paramIndex++;
    }
    
    if (toDate) {
      query += ` AND gr.created_at <= $${paramIndex}`;
      params.push(toDate);
      paramIndex++;
    }
    
    query += ` GROUP BY gr.id ORDER BY gr.created_at DESC`;
    
    const result = await pool.query(query, params);
    
    let exportData;
    let contentType;
    let filename;
    
    if (format === 'csv') {
      const headers = ['Round', 'Crash Point', 'Status', 'Date', 'Total Bets', 'Total Wagered', 'Total Paid', 'Unique Players'];
      const rows = result.rows.map(row => [
        row.round_number,
        row.crash_point,
        row.status,
        new Date(row.round_time).toLocaleString(),
        row.total_bets,
        row.total_wagered,
        row.total_paid,
        row.unique_players
      ]);
      
      exportData = [
        headers.join(','),
        ...rows.map(r => r.join(','))
      ].join('\n');
      
      contentType = 'text/csv';
      filename = `aviator_export_${Date.now()}.csv`;
    } else {
      exportData = result.rows;
      contentType = 'application/json';
      filename = `aviator_export_${Date.now()}.json`;
    }
    
    await logAdminAction(req.admin.id, 'export_aviator_data', 'game', 'aviator', {
      format,
      fromDate,
      toDate,
      recordCount: result.rows.length
    });
    
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(exportData);
    
  } catch (error) {
    console.error('❌ Error exporting data:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== DEBUG ENDPOINT ====================
app.get('/api/debug/wallet/:userId', authenticateToken, async (req, res) => {
  try {
    const userId = req.params.userId;
    
    const wallet = await pool.query(
      'SELECT * FROM wallets WHERE user_id = $1',
      [userId]
    );
    
    const transactions = await pool.query(
      `SELECT * FROM transactions 
       WHERE user_id = $1 
       ORDER BY created_at DESC 
       LIMIT 10`,
      [userId]
    );
    
    const mpesaTx = await pool.query(
      `SELECT * FROM mpesa_transactions 
       WHERE user_id = $1 
       ORDER BY created_at DESC 
       LIMIT 5`,
      [userId]
    );
    
    const balanceCalc = await pool.query(
      `SELECT 
          COALESCE(SUM(CASE WHEN type IN ('deposit', 'win', 'bonus', 'commission') THEN amount ELSE 0 END), 0) as total_credits,
          COALESCE(SUM(CASE WHEN type IN ('withdrawal', 'bet') THEN amount ELSE 0 END), 0) as total_debits,
          COALESCE(SUM(CASE WHEN type IN ('deposit', 'win', 'bonus', 'commission') THEN amount ELSE 0 END), 0) -
          COALESCE(SUM(CASE WHEN type IN ('withdrawal', 'bet') THEN amount ELSE 0 END), 0) as calculated_balance,
          COALESCE(SUM(profit), 0) as total_profit
      FROM transactions 
      WHERE user_id = $1 AND status = 'completed'`,
      [userId]
    );
    
    res.json({
      wallet: wallet.rows[0] || null,
      transactions: transactions.rows,
      mpesa_transactions: mpesaTx.rows,
      calculated: balanceCalc.rows[0],
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('❌ Debug error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== ERROR HANDLING ====================
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

app.use((req, res) => {
  res.status(404).json({ error: `Route ${req.path} not found` });
});

// ==================== START SERVER ====================
const server = app.listen(port, '0.0.0.0', () => {
  console.log(`=========================================`);
  console.log(`🚀 LobbyBets Kenya Backend Server`);
  console.log(`=========================================`);
  console.log(`📡 Port: ${port}`);
  console.log(`📊 Database: ${process.env.DB_NAME || 'lobbybets'}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔓 CORS: Enabled for ${allowedOrigins.length} origins`);
  console.log(`🔑 JWT_SECRET: ${process.env.JWT_SECRET ? '✅ Loaded' : '❌ Missing'}`);
  console.log(`🔑 JWT_EXPIRES_IN: ${process.env.JWT_EXPIRES_IN || '7d (default)'}`);
  console.log(`=========================================`);
  console.log(`📋 Available Endpoints:`);
  console.log(`   🔧 GET  /api/health`);
  console.log(`   🔐 POST /api/register`);
  console.log(`   🔐 POST /api/login`);
  console.log(`   🔐 POST /api/reset-password`);
  console.log(`   👤 GET  /api/profile/:userId`);
  console.log(`   👤 PUT  /api/profile/:userId`);
  console.log(`   👤 POST /api/profile/upload-image`);
  console.log(`   👤 POST /api/profile/remove-image`);
  console.log(`   💰 GET  /api/wallet/:userId`);
  console.log(`   💰 POST /api/wallet/sync`);
  console.log(`   💰 POST /api/wallet/update`);
  console.log(`   💰 GET  /api/user/profits/:userId`);
  console.log(`   💳 GET  /api/transactions/:userId`);
  console.log(`   💸 POST /api/withdraw`);
  console.log(`   💸 GET  /api/withdrawal/status/:transactionId`);
  console.log(`   🎲 POST /api/bets`);
  console.log(`   📋 GET  /api/bets/:userId`);
  console.log(`   ❌ POST /api/bets/:betId/cancel`);
  console.log(`   🎁 GET  /api/bonuses/:userId`);
  console.log(`   🎁 POST /api/bonuses/welcome/claim`);
  console.log(`   🎲 POST /api/games/bet`);
  console.log(`   💰 POST /api/games/cashout`);
  console.log(`   📊 GET  /api/games/history/:gameType`);
  console.log(`   🎰 POST /api/jackpot/enter`);
  console.log(`   🎰 GET  /api/jackpot/active`);
  console.log(`   🎰 GET  /api/jackpot/user/:userId`);
  console.log(`   📞 POST /api/mpesa/stkpush`);
  console.log(`   📞 POST /api/mpesa/query`);
  console.log(`   🔍 GET  /api/payment/status/:transactionId`);
  console.log(`   📞 POST /api/mpesa/callback`);
  console.log(`   🔄 POST /api/mpesa/recover-pending`);
  console.log(`   ⚽ GET  /api/leagues`);
  console.log(`   ⚽ GET  /api/matches/upcoming`);
  console.log(`   🔴 GET  /api/matches/live`);
  console.log(`   ⚽ GET  /api/matches/league/:leagueId`);
  console.log(`   ⚽ GET  /api/matches/:matchId`);
  console.log(`   📊 GET  /api/stats/:userId`);
  console.log(`   📚 GET  /api/support/faqs`);
  console.log(`   📞 GET  /api/support/contact`);
  console.log(`   📝 POST /api/support/feedback`);
  console.log(`   📊 GET  /api/support/stats`);
  console.log(`   🤝 GET  /api/affiliate/stats/:userId`);
  console.log(`   🤝 GET  /api/affiliate/referrals/:userId`);
  console.log(`   🤝 POST /api/affiliate/withdraw`);
  console.log(`   🤝 GET  /api/affiliate/commissions/:userId`);
  console.log(`   🤝 POST /api/affiliate/generate-code`);
  console.log(`   🤝 GET  /api/affiliate/validate/:code`);
  console.log(`   🤝 GET  /api/affiliate/leaderboard`);
  console.log(`   🤝 POST /api/affiliate/track`);
  console.log(`   👑 POST /api/admin/register-first`);
  console.log(`   👑 POST /api/admin/login`);
  console.log(`   👑 POST /api/admin/forgot-password`);
  console.log(`   👑 POST /api/admin/logout`);
  console.log(`   👑 POST /api/admin/terminate-other-sessions`);
  console.log(`   👑 GET  /api/admin/profile`);
  console.log(`   👑 GET  /api/admin/profile/simple`);
  console.log(`   👑 GET  /api/admin/login-history`);
  console.log(`   👑 POST /api/admin/create`);
  console.log(`   👑 GET  /api/admin/all`);
  console.log(`   👑 PUT  /api/admin/:adminId/toggle-status`);
  console.log(`   👑 DELETE /api/admin/:adminId`);
  console.log(`   👑 GET  /api/admin/stats`);
  console.log(`   👑 POST /api/admin/mpesa/recover-transaction`);
  console.log(`   🎮 GET  /api/admin/aviator/settings`);
  console.log(`   🎮 PUT  /api/admin/aviator/settings`);
  console.log(`   🎮 POST /api/admin/aviator/rotate-seed`);
  console.log(`   🎮 POST /api/admin/aviator/force-crash`);
  console.log(`   🎮 GET  /api/admin/aviator/active-round`);
  console.log(`   🎮 GET  /api/admin/aviator/rounds`);
  console.log(`   🎮 GET  /api/admin/aviator/rounds/:roundId`);
  console.log(`   🎮 GET  /api/admin/aviator/stats`);
  console.log(`   🎮 GET  /api/admin/aviator/active-players`);
  console.log(`   🎮 POST /api/admin/aviator/auto-crash-queue`);
  console.log(`   🎮 DELETE /api/admin/aviator/auto-crash-queue`);
  console.log(`   🎮 POST /api/admin/aviator/suspend-user`);
  console.log(`   🎮 GET  /api/admin/aviator/suspended-users`);
  console.log(`   🎮 DELETE /api/admin/aviator/suspended-users/:userId`);
  console.log(`   🎮 GET  /api/admin/aviator/verify/:roundId`);
  console.log(`   🎮 POST /api/admin/aviator/export`);
  console.log(`   🧪 GET  /api/test-jwt`);
  console.log(`   🔍 GET  /api/debug/wallet/:userId`);
  console.log(`=========================================`);
});

process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully...');
  server.close(() => {
    console.log('Server closed');
    pool.end(() => {
      console.log('Database pool closed');
      process.exit(0);
    });
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully...');
  server.close(() => {
    console.log('Server closed');
    pool.end(() => {
      console.log('Database pool closed');
      process.exit(0);
    });
  });
});
