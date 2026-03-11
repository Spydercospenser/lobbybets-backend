const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
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

/// ==================== CORS CONFIGURATION ====================
// Allow requests from multiple origins
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
  'http://localhost:5001'
];

// Add regex pattern for all expo.app subdomains
const allowedOriginPatterns = [
  /\.expo\.app$/,
  /^https?:\/\/lobbybets-app--[a-z0-9]+\.expo\.app$/
];

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps, curl, Postman)
    if (!origin) return callback(null, true);
    
    // Check if origin is in the explicit list
    if (allowedOrigins.indexOf(origin) !== -1) {
      return callback(null, true);
    }
    
    // Check if origin matches any pattern
    const matchesPattern = allowedOriginPatterns.some(pattern => pattern.test(origin));
    if (matchesPattern) {
      return callback(null, true);
    }
    
    // Allow all origins in development
    if (process.env.NODE_ENV !== 'production') {
      console.log('⚠️ Development mode - allowing origin:', origin);
      return callback(null, true);
    }
    
    // Block in production
    console.log('❌ Blocked origin:', origin);
    callback(new Error('Not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'X-Requested-With'],
  exposedHeaders: ['Content-Range', 'X-Content-Range'],
  credentials: true,
  optionsSuccessStatus: 200,
  maxAge: 86400 // 24 hours
};

// Apply CORS middleware - this handles everything
app.use(cors(corsOptions));

// Simple logging middleware (no wildcard routes)
app.use((req, res, next) => {
  // Log requests (skip OPTIONS to reduce noise)
  if (req.method !== 'OPTIONS') {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  }
  next();
});

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Database connection with SSL for Render
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // Required for Render PostgreSQL
  },
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

// ==================== INITIALIZE SECURITY TABLES ====================
async function initializeSecurityTables() {
  try {
    console.log('🔐 Initializing security tables...');
    
    // Create admin_sessions table
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

    // Create admin_login_history table
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

    // Create admin_action_logs table
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

    // Add columns to admins table if they don't exist
    await pool.query(`
      ALTER TABLE admins 
      ADD COLUMN IF NOT EXISTS active_session_id VARCHAR(255),
      ADD COLUMN IF NOT EXISTS active_session_expires TIMESTAMP,
      ADD COLUMN IF NOT EXISTS last_session_created TIMESTAMP,
      ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER DEFAULT 0,
      ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP,
      ADD COLUMN IF NOT EXISTS last_failed_login TIMESTAMP
    `);

    // Create indexes
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_admin_sessions_token ON admin_sessions(session_token)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_admin_sessions_admin ON admin_sessions(admin_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_admin_sessions_active ON admin_sessions(is_active)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_admin_login_history_admin ON admin_login_history(admin_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_admin_action_logs_admin ON admin_action_logs(admin_id)`);

    console.log('✅ Security tables initialized successfully');
  } catch (error) {
    console.error('❌ Error initializing security tables:', error);
  }
}

// Test database connection on startup
pool.connect((err, client, release) => {
  if (err) {
    console.error('❌ Database connection error:', err.stack);
  } else {
    console.log('✅ Database connected successfully');
    release();
    initializeSecurityTables();
    
    // Initialize wallet triggers after connection
    initializeWalletTriggers().catch(console.error);
    
    // Initialize game functions
    initializeGameFunctions().catch(console.error);
  }
});

// ==================== INITIALIZE GAME FUNCTIONS ====================
async function initializeGameFunctions() {
  try {
    console.log('🎮 Initializing game functions...');

    // Create function to generate crash points with probability distribution
    await pool.query(`
      CREATE OR REPLACE FUNCTION generate_crash_point() RETURNS DECIMAL AS $$
      DECLARE
          random_num DECIMAL;
          crash_point DECIMAL;
      BEGIN
          random_num = random(); -- 0 to 1
          
          -- 1.00x – 2.00x (50%)
          IF random_num <= 0.50 THEN
              crash_point = 1.00 + (random() * 1.00);
          -- 2.00x – 2.99x (20%)
          ELSIF random_num <= 0.70 THEN
              crash_point = 2.00 + (random() * 0.99);
          -- 3.00x – 5.00x (15%)
          ELSIF random_num <= 0.85 THEN
              crash_point = 3.00 + (random() * 2.00);
          -- 5.00x – 8.00x (6%)
          ELSIF random_num <= 0.91 THEN
              crash_point = 5.00 + (random() * 3.00);
          -- 8.00x – 13x (3%)
          ELSIF random_num <= 0.94 THEN
              crash_point = 8.00 + (random() * 5.00);
          -- 13x – 19x (2.5%)
          ELSIF random_num <= 0.965 THEN
              crash_point = 13.00 + (random() * 6.00);
          -- 19x – 29x (1.5%)
          ELSIF random_num <= 0.98 THEN
              crash_point = 19.00 + (random() * 10.00);
          -- 29x – 49x (1%)
          ELSIF random_num <= 0.99 THEN
              crash_point = 29.00 + (random() * 20.00);
          -- 49x – 75x (0.5%)
          ELSIF random_num <= 0.995 THEN
              crash_point = 49.00 + (random() * 26.00);
          -- 75x – 130x (0.5%)
          ELSE
              crash_point = 75.00 + (random() * 55.00);
          END IF;
          
          RETURN ROUND(crash_point::numeric, 2);
      END;
      $$ LANGUAGE plpgsql;
    `);

    // Create function to settle Aviator bets
    await pool.query(`
      CREATE OR REPLACE FUNCTION settle_aviator_bets() RETURNS void AS $$
      BEGIN
          UPDATE bets 
          SET status = 'lost',
              settled_at = NOW(),
              actual_winnings = 0
          WHERE game_type = 'aviator' 
            AND status = 'pending'
            AND created_at < NOW() - INTERVAL '5 minutes';
          
          RAISE NOTICE 'Settled % old Aviator bets', (SELECT COUNT(*) FROM bets WHERE game_type = 'aviator' AND status = 'lost' AND settled_at > NOW() - INTERVAL '1 minute');
      END;
      $$ LANGUAGE plpgsql;
    `);

    // Create function to get user balance
    await pool.query(`
      CREATE OR REPLACE FUNCTION get_user_balance(p_user_id INTEGER)
      RETURNS TABLE (
          main_balance DECIMAL,
          bonus_balance DECIMAL,
          affiliate_balance DECIMAL,
          pending_withdrawals DECIMAL,
          total_balance DECIMAL
      ) AS $$
      BEGIN
          RETURN QUERY
          SELECT 
              COALESCE(w.main_balance, 0) as main_balance,
              COALESCE(w.bonus_balance, 0) as bonus_balance,
              COALESCE(w.affiliate_balance, 0) as affiliate_balance,
              COALESCE((
                  SELECT SUM(amount) 
                  FROM transactions 
                  WHERE user_id = p_user_id 
                  AND type = 'withdrawal' 
                  AND status = 'pending'
              ), 0) as pending_withdrawals,
              COALESCE(w.main_balance, 0) + COALESCE(w.bonus_balance, 0) + COALESCE(w.affiliate_balance, 0) as total_balance
          FROM wallets w
          WHERE w.user_id = p_user_id;
      END;
      $$ LANGUAGE plpgsql;
    `);

    // Create function to cashout Aviator bet
    await pool.query(`
      CREATE OR REPLACE FUNCTION cashout_aviator_bet(
          p_bet_id INTEGER,
          p_user_id INTEGER,
          p_multiplier DECIMAL
      ) RETURNS TABLE (
          win_amount DECIMAL,
          new_balance DECIMAL
      ) AS $$
      DECLARE
          v_bet RECORD;
          v_current_balance DECIMAL;
          v_win_amount DECIMAL;
      BEGIN
          -- Get bet details and lock
          SELECT * INTO v_bet
          FROM bets 
          WHERE id = p_bet_id AND user_id = p_user_id AND status = 'pending'
          FOR UPDATE;
          
          IF NOT FOUND THEN
              RAISE EXCEPTION 'Bet not found or already settled';
          END IF;
          
          -- Calculate win
          v_win_amount = v_bet.stake * p_multiplier;
          
          -- Update bet
          UPDATE bets 
          SET status = 'cashed_out',
              cashout_multiplier = p_multiplier,
              actual_winnings = v_win_amount,
              settled_at = NOW()
          WHERE id = p_bet_id;
          
          -- Get current balance
          SELECT main_balance INTO v_current_balance
          FROM wallets WHERE user_id = p_user_id;
          
          -- Add winnings to wallet
          UPDATE wallets 
          SET main_balance = main_balance + v_win_amount,
              lifetime_winnings = lifetime_winnings + v_win_amount
          WHERE user_id = p_user_id;
          
          -- Create transaction
          INSERT INTO transactions (
              user_id, type, amount, status, description, reference,
              balance_before, balance_after
          ) VALUES (
              p_user_id, 'win', v_win_amount, 'completed',
              'Cashed out at ' || p_multiplier || 'x',
              'WIN-' || floor(random() * 1000000)::text,
              v_current_balance, v_current_balance + v_win_amount
          );
          
          RETURN QUERY
          SELECT v_win_amount, v_current_balance + v_win_amount;
      END;
      $$ LANGUAGE plpgsql;
    `);

    // Create function to process withdrawal
    await pool.query(`
      CREATE OR REPLACE FUNCTION process_withdrawal(
          p_user_id INTEGER,
          p_amount DECIMAL,
          p_phone_number VARCHAR,
          p_reference VARCHAR
      ) RETURNS INTEGER AS $$
      DECLARE
          v_wallet_id INTEGER;
          v_current_balance DECIMAL;
          v_transaction_id INTEGER;
      BEGIN
          -- Get wallet and lock it
          SELECT id, main_balance INTO v_wallet_id, v_current_balance
          FROM wallets WHERE user_id = p_user_id FOR UPDATE;
          
          -- Check sufficient balance
          IF v_current_balance < p_amount THEN
              RAISE EXCEPTION 'Insufficient balance';
          END IF;
          
          -- Create transaction record
          INSERT INTO transactions (
              user_id, type, amount, status, description, reference,
              balance_before, balance_after
          ) VALUES (
              p_user_id, 'withdrawal', p_amount, 'pending',
              'Withdrawal to ' || p_phone_number, p_reference,
              v_current_balance, v_current_balance - p_amount
          ) RETURNING id INTO v_transaction_id;
          
          -- Update wallet (temporarily deduct)
          UPDATE wallets 
          SET main_balance = main_balance - p_amount,
              lifetime_withdrawals = lifetime_withdrawals + p_amount
          WHERE user_id = p_user_id;
          
          -- Record in mpesa_transactions
          INSERT INTO mpesa_transactions (
              user_id, phone_number, amount, reference, type,
              payment_type, status, transaction_id
          ) VALUES (
              p_user_id, p_phone_number, p_amount, p_reference,
              'withdrawal', 'stk', 'pending', v_transaction_id
          );
          
          RETURN v_transaction_id;
      END;
      $$ LANGUAGE plpgsql;
    `);

    // Create function to claim welcome bonus
    await pool.query(`
      CREATE OR REPLACE FUNCTION claim_welcome_bonus(p_user_id INTEGER)
      RETURNS DECIMAL AS $$
      DECLARE
          v_bonus_id INTEGER;
          v_bonus_amount DECIMAL;
          v_already_claimed BOOLEAN;
          v_current_balance DECIMAL;
      BEGIN
          -- Check if already claimed
          SELECT EXISTS(
              SELECT 1 FROM user_bonuses ub
              JOIN bonuses b ON ub.bonus_id = b.id
              WHERE ub.user_id = p_user_id AND b.type = 'welcome'
          ) INTO v_already_claimed;
          
          IF v_already_claimed THEN
              RAISE EXCEPTION 'Welcome bonus already claimed';
          END IF;
          
          -- Get bonus details
          SELECT id, amount INTO v_bonus_id, v_bonus_amount
          FROM bonuses WHERE type = 'welcome' LIMIT 1;
          
          -- Get current balance
          SELECT main_balance INTO v_current_balance
          FROM wallets WHERE user_id = p_user_id;
          
          -- Record bonus claim
          INSERT INTO user_bonuses (user_id, bonus_id, amount, status, claimed_at)
          VALUES (p_user_id, v_bonus_id, v_bonus_amount, 'claimed', NOW());
          
          -- Add to wallet
          UPDATE wallets 
          SET bonus_balance = bonus_balance + v_bonus_amount,
              main_balance = main_balance + v_bonus_amount
          WHERE user_id = p_user_id;
          
          -- Create transaction
          INSERT INTO transactions (
              user_id, type, amount, status, description, reference,
              balance_before, balance_after
          ) VALUES (
              p_user_id, 'bonus', v_bonus_amount, 'completed',
              'Welcome Bonus', 'BONUS-' || floor(random() * 1000000)::text,
              v_current_balance, v_current_balance + v_bonus_amount
          );
          
          RETURN v_bonus_amount;
      END;
      $$ LANGUAGE plpgsql;
    `);

    console.log('✅ Game functions initialized successfully');
  } catch (error) {
    console.error('❌ Error initializing game functions:', error);
  }
}

// ==================== INITIALIZE WALLET TRIGGERS ====================
async function initializeWalletTriggers() {
  try {
    console.log('💰 Initializing wallet triggers...');
    
    // Add updated_at column if it doesn't exist
    await pool.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns 
          WHERE table_name = 'wallets' AND column_name = 'updated_at'
        ) THEN
          ALTER TABLE wallets ADD COLUMN updated_at TIMESTAMP DEFAULT NOW();
        END IF;
        
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.columns 
          WHERE table_name = 'wallets' AND column_name = 'last_transaction_at'
        ) THEN
          ALTER TABLE wallets ADD COLUMN last_transaction_at TIMESTAMP;
        END IF;
      END $$;
    `);

    // Create function to sync wallet on transaction
    await pool.query(`
      CREATE OR REPLACE FUNCTION sync_wallet_on_transaction()
      RETURNS TRIGGER AS $$
      BEGIN
        -- Update wallet based on all completed transactions
        UPDATE wallets 
        SET 
          main_balance = (
            SELECT COALESCE(SUM(CASE WHEN type IN ('deposit', 'win', 'bonus') THEN amount ELSE 0 END), 0) -
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

    // Create function to handle M-PESA completions
    await pool.query(`
      CREATE OR REPLACE FUNCTION handle_mpesa_completion()
      RETURNS TRIGGER AS $$
      DECLARE
        current_wallet_balance DECIMAL;
      BEGIN
        -- Only process when status changes to completed
        IF NEW.status = 'completed' AND (OLD.status IS NULL OR OLD.status != 'completed') THEN
          
          -- Get current wallet balance
          SELECT COALESCE(main_balance, 0) INTO current_wallet_balance
          FROM wallets WHERE user_id = NEW.user_id;
          
          -- Insert into transactions if not exists
          INSERT INTO transactions (
            user_id,
            type,
            amount,
            status,
            description,
            reference,
            balance_before,
            balance_after,
            created_at
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
            NOW()
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

    console.log('✅ Wallet triggers initialized successfully');
  } catch (error) {
    console.error('❌ Error initializing wallet triggers:', error);
  }
}

// ==================== HELPER FUNCTIONS ====================
const generateReferralCode = () => {
  return 'REF' + Math.random().toString(36).substring(2, 8).toUpperCase();
};

const formatPhoneForMPesa = (phone) => {
  // Remove any non-numeric characters
  let cleaned = phone.replace(/[^0-9]/g, '');
  
  // Convert 07XX to 2547XX
  if (cleaned.startsWith('0')) {
    cleaned = '254' + cleaned.substring(1);
  } else if (cleaned.startsWith('7')) {
    cleaned = '254' + cleaned;
  }
  
  return cleaned;
};

const normalizePhoneForDatabase = (phone) => {
  // Remove all non-numeric characters
  let cleaned = phone.replace(/[^0-9]/g, '');
  
  // If it starts with 0, replace with 254
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

const generatePassword = (shortCode, passkey, timestamp) => {
  const str = shortCode + passkey + timestamp;
  return crypto.createHash('sha256').update(str).digest('base64');
};

// ==================== ADMIN SECURITY HELPER FUNCTIONS ====================

// Function to handle failed login attempts
async function handleFailedLogin(email) {
  try {
    const admin = await pool.query('SELECT id FROM admins WHERE email = $1', [email]);
    if (admin.rows.length === 0) return;

    const adminId = admin.rows[0].id;

    // Increment failed attempts and maybe lock account
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

// Function to check if admin is locked
async function isAdminLocked(adminId) {
  try {
    const result = await pool.query(
      'SELECT locked_until FROM admins WHERE id = $1',
      [adminId]
    );
    if (result.rows.length === 0) return false;
    return result.rows[0].locked_until && new Date(result.rows[0].locked_until) > new Date();
  } catch (error) {
    console.error('Error checking admin lock:', error);
    return false;
  }
}

// Function to reset failed login attempts
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

// Helper function to log admin actions
async function logAdminAction(adminId, action, targetType, targetId, details) {
  try {
    await pool.query(
      `INSERT INTO admin_action_logs (
        admin_id, action, target_type, target_id, details, ip_address, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
      [adminId, action, targetType, targetId, JSON.stringify(details), null]
    );
  } catch (error) {
    console.error('Error logging admin action:', error);
  }
}

// ==================== AUTHENTICATION MIDDLEWARE ====================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  console.log('🔐 Auth header received:', authHeader ? 'Yes' : 'No');
  console.log('🔐 Auth header value:', authHeader ? authHeader.substring(0, 30) + '...' : 'None');
  
  if (!token) {
    console.log('❌ No token provided in request');
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }
  
  console.log('🔑 Token received (first 30 chars):', token.substring(0, 30) + '...');
  console.log('🔑 Token length:', token.length);
  console.log('🔑 Token parts:', token.split('.').length);
  
  // Check if token has 3 parts (header.payload.signature)
  const parts = token.split('.');
  if (parts.length !== 3) {
    console.error('❌ Token does not have 3 parts, has:', parts.length);
    return res.status(403).json({ error: 'Invalid token format' });
  }
  
  // Try to decode the payload without verification to see what's inside
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    console.log('📦 Token payload (decoded):', {
      userId: payload.userId,
      phone: payload.phone ? 'present' : 'missing',
      exp: payload.exp ? new Date(payload.exp * 1000).toLocaleString() : 'missing',
      iat: payload.iat ? new Date(payload.iat * 1000).toLocaleString() : 'missing'
    });
    
    // Check if token is expired
    if (payload.exp) {
      const now = Math.floor(Date.now() / 1000);
      if (payload.exp < now) {
        console.log('⏰ Token EXPIRED at:', new Date(payload.exp * 1000).toLocaleString());
        console.log('⏰ Current time:', new Date().toLocaleString());
      } else {
        console.log('⏰ Token valid until:', new Date(payload.exp * 1000).toLocaleString());
      }
    }
  } catch (decodeError) {
    console.error('❌ Could not decode token payload:', decodeError.message);
  }
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error('❌ JWT Verification failed:');
      console.error('   - Name:', err.name);
      console.error('   - Message:', err.message);
      
      if (err.name === 'JsonWebTokenError') {
        console.error('   - This usually means:');
        console.error('     1. JWT_SECRET mismatch between server and client');
        console.error('     2. Token was tampered with');
        console.error('     3. Token was generated with a different secret');
        return res.status(403).json({ error: 'Invalid token signature' });
      } else if (err.name === 'TokenExpiredError') {
        console.error('   - Token expired at:', err.expiredAt);
        return res.status(403).json({ error: 'Token expired' });
      } else {
        return res.status(403).json({ error: 'Invalid or expired token' });
      }
    }
    
    console.log('✅ Token verified successfully for user:', user.userId);
    req.user = user;
    next();
  });
};

// ==================== TEST JWT ENDPOINT ====================
app.get('/api/test-jwt', (req, res) => {
  try {
    // Generate a test token
    const expiresIn = process.env.JWT_EXPIRES_IN || '7d';
    const testToken = jwt.sign(
      { test: 'data', userId: 'test-user' },
      process.env.JWT_SECRET,
      { expiresIn: expiresIn }
    );
    
    // Verify it immediately
    const verified = jwt.verify(testToken, process.env.JWT_SECRET);
    
    // Decode to check expiration
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

// ==================== ADMIN HELPER FUNCTIONS ====================

// Check if user is admin
const isAdmin = async (userId) => {
  try {
    const result = await pool.query(
      'SELECT "role" FROM profiles WHERE id = $1',
      [userId]
    );
    return result.rows[0]?.role === 'admin' || result.rows[0]?.role === 'super_admin';
  } catch (error) {
    console.error('❌ Error checking admin status:', error);
    return false;
  }
};

// Check if user is super admin
const isSuperAdmin = async (userId) => {
  try {
    const result = await pool.query(
      'SELECT "role" FROM profiles WHERE id = $1',
      [userId]
    );
    return result.rows[0]?.role === 'super_admin';
  } catch (error) {
    console.error('❌ Error checking super admin status:', error);
    return false;
  }
};

// ==================== ENHANCED ADMIN AUTHENTICATION MIDDLEWARE ====================
const authenticateAdmin = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    // Verify JWT
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Check if session exists and is active in database
    const session = await pool.query(
      `SELECT s.*, a.role, a.is_active, a.locked_until
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
    
    // Check if account is still active
    if (!sessionData.is_active) {
      await pool.query(
        'UPDATE admin_sessions SET is_active = false WHERE session_token = $1',
        [token]
      );
      return res.status(403).json({ error: 'Account is deactivated' });
    }
    
    // Check if account is locked
    if (sessionData.locked_until && new Date(sessionData.locked_until) > new Date()) {
      await pool.query(
        'UPDATE admin_sessions SET is_active = false WHERE session_token = $1',
        [token]
      );
      return res.status(403).json({ error: 'Account is locked' });
    }
    
    // Update last activity
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
      // Deactivate expired session in database
      await pool.query(
        'UPDATE admin_sessions SET is_active = false WHERE session_token = $1',
        [token]
      );
      return res.status(401).json({ error: 'Session expired' });
    }
    
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// ==================== PUBLIC ADMIN ROUTES ====================
// These routes DON'T need authentication

// Register first super admin (only works if no admins exist)
app.post('/api/admin/register-first', async (req, res) => {
  const { full_name, email, phone, password } = req.body;
  
  try {
    // Validate input
    if (!full_name || !email || !phone || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    // Check if any admin already exists
    const adminCount = await pool.query('SELECT COUNT(*) FROM admins');
    
    if (parseInt(adminCount.rows[0].count) > 0) {
      return res.status(403).json({ 
        error: 'Initial setup already completed. Maximum 3 admins allowed.' 
      });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create first super admin
    const result = await pool.query(
      `INSERT INTO admins (full_name, email, phone, password_hash, role) 
       VALUES ($1, $2, $3, $4, 'super_admin') 
       RETURNING id, full_name, email, phone, role, created_at`,
      [full_name, email, phone, hashedPassword]
    );
    
    const admin = result.rows[0];
    
    // Generate JWT
    const token = jwt.sign(
      { adminId: admin.id, email: admin.email, role: admin.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    console.log('✅ First super admin created:', email);
    console.log('📊 Total admins now: 1');
    
    res.json({
      success: true,
      message: 'Super admin created successfully',
      token,
      admin
    });
    
  } catch (error) {
    console.error('❌ Error creating first admin:', error);
    
    if (error.code === '23505') { // Unique violation
      return res.status(400).json({ error: 'Email or phone already exists' });
    }
    
    res.status(500).json({ error: error.message });
  }
});

// Enhanced admin login with session management, failed attempt tracking, and single session enforcement
app.post('/api/admin/login', async (req, res) => {
  const { email, password, deviceInfo, userAgent } = req.body;
  const ipAddress = req.ip || req.connection.remoteAddress;
  
  try {
    console.log('👑 Admin login attempt for:', email);
    console.log('📱 Device:', deviceInfo || 'Unknown');
    console.log('🌐 IP:', ipAddress);
    
    // Get admin details with security fields
    const result = await pool.query(
      `SELECT id, full_name, email, phone, role, password_hash, 
              is_active, failed_login_attempts, locked_until
       FROM admins WHERE email = $1`,
      [email]
    );
    
    if (result.rows.length === 0) {
      // Log failed attempt (no such user)
      await pool.query(
        `INSERT INTO admin_login_history (email, ip_address, user_agent, login_status, failure_reason)
         VALUES ($1, $2, $3, 'failed', 'User not found')`,
        [email, ipAddress, userAgent || null]
      );
      
      console.log('❌ Admin not found:', email);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const admin = result.rows[0];
    
    // Check if account is locked
    if (admin.locked_until && new Date(admin.locked_until) > new Date()) {
      const lockTimeRemaining = Math.ceil((new Date(admin.locked_until) - new Date()) / 60000);
      
      await pool.query(
        `INSERT INTO admin_login_history (admin_id, email, ip_address, user_agent, login_status, failure_reason)
         VALUES ($1, $2, $3, $4, 'locked', $5)`,
        [admin.id, email, ipAddress, userAgent || null, `Account locked for ${lockTimeRemaining} minutes`]
      );
      
      console.log('❌ Admin account locked:', email, 'for', lockTimeRemaining, 'minutes');
      return res.status(403).json({ 
        error: `Account is locked. Try again in ${lockTimeRemaining} minutes.` 
      });
    }
    
    // Check if account is active
    if (!admin.is_active) {
      await pool.query(
        `INSERT INTO admin_login_history (admin_id, email, ip_address, user_agent, login_status, failure_reason)
         VALUES ($1, $2, $3, $4, 'failed', 'Account deactivated')`,
        [admin.id, email, ipAddress, userAgent || null]
      );
      
      console.log('❌ Admin account deactivated:', email);
      return res.status(403).json({ error: 'Account is deactivated. Contact super admin.' });
    }
    
    // Verify password
    const validPassword = await bcrypt.compare(password, admin.password_hash);
    if (!validPassword) {
      // Handle failed login attempt using database function
      await handleFailedLogin(email);
      
      // Log failed attempt
      await pool.query(
        `INSERT INTO admin_login_history (admin_id, email, ip_address, user_agent, login_status, failure_reason)
         VALUES ($1, $2, $3, $4, 'failed', 'Invalid password')`,
        [admin.id, email, ipAddress, userAgent || null]
      );
      
      console.log('❌ Invalid password for admin:', email);
      
      // Check if account just got locked
      const locked = await isAdminLocked(admin.id);
      if (locked) {
        return res.status(403).json({ 
          error: 'Too many failed attempts. Account locked for 30 minutes.' 
        });
      }
      
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check for existing active sessions
    const existingSession = await pool.query(
      `SELECT * FROM admin_sessions 
       WHERE admin_id = $1 AND is_active = true AND expires_at > NOW()`,
      [admin.id]
    );
    
    if (existingSession.rows.length > 0) {
      console.log('⚠️ Terminating', existingSession.rows.length, 'existing session(s) for admin:', email);
      
      // Terminate existing sessions
      await pool.query(
        `UPDATE admin_sessions 
         SET is_active = false 
         WHERE admin_id = $1 AND is_active = true`,
        [admin.id]
      );
      
      // Log session termination
      await pool.query(
        `INSERT INTO admin_login_history (admin_id, email, ip_address, user_agent, login_status, failure_reason)
         VALUES ($1, $2, $3, $4, 'session_terminated', 'Previous session terminated due to new login')`,
        [admin.id, email, ipAddress, userAgent || null]
      );
    }
    
    // Generate session token (JWT with shorter expiry for session management)
    const sessionToken = jwt.sign(
      { 
        adminId: admin.id, 
        email: admin.email, 
        role: admin.role,
        sessionId: crypto.randomBytes(16).toString('hex'),
        loginTime: Date.now()
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' } // Sessions last 24 hours
    );
    
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 24);
    
    // Create new session
    await pool.query(
      `INSERT INTO admin_sessions 
       (admin_id, session_token, device_info, ip_address, user_agent, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [admin.id, sessionToken, deviceInfo || null, ipAddress, userAgent || null, expiresAt]
    );
    
    // Reset failed login attempts
    await resetFailedLogin(admin.id);
    
    // Update last login info
    await pool.query(
      `UPDATE admins 
       SET last_login_at = NOW(), 
           last_login_ip = $1
       WHERE id = $2`,
      [ipAddress, admin.id]
    );
    
    // Log successful login
    await pool.query(
      `INSERT INTO admin_login_history (admin_id, email, ip_address, user_agent, login_status, session_token)
       VALUES ($1, $2, $3, $4, 'success', $5)`,
      [admin.id, email, ipAddress, userAgent || null, sessionToken]
    );
    
    // Log the login action
    await pool.query(
      `INSERT INTO admin_action_logs (admin_id, admin_email, action_type, action_details, ip_address, user_agent, session_token)
       VALUES ($1, $2, 'login', $3, $4, $5, $6)`,
      [admin.id, email, JSON.stringify({ method: 'password', deviceInfo }), ipAddress, userAgent || null, sessionToken]
    );
    
    console.log('✅ Admin login successful:', admin.email, 'Role:', admin.role);
    console.log('🔐 Active sessions:', existingSession.rows.length, 'terminated, 1 new session created');
    console.log('⏰ Session expires:', expiresAt.toLocaleString());
    
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

// Enhanced forgot password with security checks
app.post('/api/admin/forgot-password', async (req, res) => {
  const { email, newPassword, confirmPassword } = req.body;
  const ipAddress = req.ip || req.connection.remoteAddress;
  
  try {
    console.log('🔑 Password reset requested for:', email);
    console.log('🌐 IP:', ipAddress);
    
    // Validate input
    if (!email || !newPassword || !confirmPassword) {
      return res.status(400).json({ error: 'Email, new password, and confirm password are required' });
    }
    
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }
    
    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    
    // Check password strength
    const hasUpperCase = /[A-Z]/.test(newPassword);
    const hasLowerCase = /[a-z]/.test(newPassword);
    const hasNumbers = /\d/.test(newPassword);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(newPassword);
    
    if (!(hasUpperCase && hasLowerCase && hasNumbers && hasSpecialChar)) {
      return res.status(400).json({ 
        error: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character' 
      });
    }
    
    // Check if admin exists and get details
    const admin = await pool.query(
      'SELECT id, full_name, is_active, locked_until FROM admins WHERE email = $1',
      [email]
    );
    
    if (admin.rows.length === 0) {
      console.log('❌ Admin not found for password reset:', email);
      // Don't reveal that admin doesn't exist
      return res.json({ 
        success: true, 
        message: 'If the email exists, a password reset has been processed.' 
      });
    }
    
    const adminData = admin.rows[0];
    
    // Check if account is locked
    if (adminData.locked_until && new Date(adminData.locked_until) > new Date()) {
      console.log('❌ Password reset attempted on locked account:', email);
      return res.status(403).json({ 
        error: 'Account is locked. Cannot reset password at this time.' 
      });
    }
    
    // Check if account is active
    if (!adminData.is_active) {
      console.log('❌ Password reset attempted on deactivated account:', email);
      return res.status(403).json({ error: 'Account is deactivated. Contact super admin.' });
    }
    
    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 12); // Increased salt rounds
    
    // Update password and reset failed attempts
    await pool.query(
      `UPDATE admins 
       SET password_hash = $1, 
           updated_at = NOW(),
           failed_login_attempts = 0,
           locked_until = NULL
       WHERE id = $2`,
      [hashedPassword, adminData.id]
    );
    
    // Terminate all active sessions for security
    await pool.query(
      `UPDATE admin_sessions 
       SET is_active = false 
       WHERE admin_id = $1 AND is_active = true`,
      [adminData.id]
    );
    
    // Clear active session in admins table
    await pool.query(
      `UPDATE admins 
       SET active_session_id = NULL,
           active_session_expires = NULL
       WHERE id = $1`,
      [adminData.id]
    );
    
    // Log password reset
    await pool.query(
      `INSERT INTO admin_action_logs (admin_id, admin_email, action_type, action_details, ip_address)
       VALUES ($1, $2, 'password_reset', $3, $4)`,
      [adminData.id, email, JSON.stringify({ method: 'forgot_password' }), ipAddress]
    );
    
    // Log in history
    await pool.query(
      `INSERT INTO admin_login_history (admin_id, email, ip_address, login_status, failure_reason)
       VALUES ($1, $2, $3, 'password_reset', 'Password reset completed')`,
      [adminData.id, email, ipAddress]
    );
    
    console.log('✅ Password reset successful for:', email);
    console.log('🔐 All sessions terminated for security');
    
    res.json({
      success: true,
      message: 'Password reset successfully. All existing sessions have been terminated for security.'
    });
    
  } catch (error) {
    console.error('❌ Password reset error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Logout endpoint
app.post('/api/admin/logout', authenticateAdmin, async (req, res) => {
  const sessionToken = req.headers['authorization']?.split(' ')[1];
  const ipAddress = req.ip || req.connection.remoteAddress;
  
  try {
    console.log('👋 Admin logout for:', req.admin.email);
    
    // Deactivate session
    const result = await pool.query(
      `UPDATE admin_sessions 
       SET is_active = false 
       WHERE session_token = $1
       RETURNING admin_id`,
      [sessionToken]
    );
    
    if (result.rows.length > 0) {
      const adminId = result.rows[0].admin_id;
      
      // Clear active session in admins table
      await pool.query(
        `UPDATE admins 
         SET active_session_id = NULL,
             active_session_expires = NULL
         WHERE id = $1`,
        [adminId]
      );
      
      // Log logout
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

// Force logout all other sessions (for security)
app.post('/api/admin/terminate-other-sessions', authenticateAdmin, async (req, res) => {
  const sessionToken = req.headers['authorization']?.split(' ')[1];
  const ipAddress = req.ip || req.connection.remoteAddress;
  
  try {
    console.log('🔒 Terminating other sessions for:', req.admin.email);
    
    // Terminate all other sessions
    const result = await pool.query(
      `UPDATE admin_sessions 
       SET is_active = false 
       WHERE admin_id = $1 
         AND session_token != $2 
         AND is_active = true
       RETURNING id`,
      [req.admin.id, sessionToken]
    );
    
    // Log action
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

// Get current admin profile with session info
app.get('/api/admin/profile', authenticateAdmin, async (req, res) => {
  try {
    // Get admin details with session info
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
    
    // Get current session details
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

// Get login history (super admin only)
app.get('/api/admin/login-history', authenticateAdmin, async (req, res) => {
  try {
    // Only super admin can view all login history
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

// ==================== PROTECTED ADMIN ROUTES ====================
// These routes REQUIRE authentication (use authenticateAdmin middleware)

// Create new admin (super admin only) - Limited to 3 total admins
app.post('/api/admin/create', authenticateAdmin, async (req, res) => {
  const { full_name, email, phone, password, role = 'admin' } = req.body;
  
  try {
    // Check if requesting admin is super admin
    if (req.admin.role !== 'super_admin') {
      console.log('❌ Unauthorized attempt to create admin by:', req.admin.email);
      return res.status(403).json({ error: 'Only super admins can create new admins' });
    }
    
    // Validate input
    if (!full_name || !email || !phone || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    // Check if we've reached the limit of 3 admins
    const adminCount = await pool.query('SELECT COUNT(*) FROM admins');
    const currentCount = parseInt(adminCount.rows[0].count);
    
    if (currentCount >= 3) {
      console.log('❌ Cannot create more admins. Current count:', currentCount);
      return res.status(403).json({ 
        error: 'Maximum of 3 admins allowed. Cannot create more.',
        currentCount,
        maxAllowed: 3
      });
    }
    
    // Check if email or phone already exists
    const existing = await pool.query(
      'SELECT id FROM admins WHERE email = $1 OR phone = $2',
      [email, phone]
    );
    
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Email or phone already exists' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create new admin
    const result = await pool.query(
      `INSERT INTO admins (full_name, email, phone, password_hash, role, created_by) 
       VALUES ($1, $2, $3, $4, $5, $6) 
       RETURNING id, full_name, email, phone, role, created_at`,
      [full_name, email, phone, hashedPassword, role, req.admin.id]
    );
    
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
    console.error('❌ Error creating admin:', error);
    
    if (error.code === '23505') {
      return res.status(400).json({ error: 'Email or phone already exists' });
    }
    
    res.status(500).json({ error: error.message });
  }
});

// Get all admins (super admin only)
app.get('/api/admin/all', authenticateAdmin, async (req, res) => {
  try {
    // Check if requesting admin is super admin
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
    
    // Get total count
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

// Get current admin profile (authenticated)
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

// Deactivate/reactivate admin (super admin only)
app.put('/api/admin/:adminId/toggle-status', authenticateAdmin, async (req, res) => {
  const { adminId } = req.params;
  
  try {
    // Check if requesting admin is super admin
    if (req.admin.role !== 'super_admin') {
      console.log('❌ Unauthorized attempt to toggle status by:', req.admin.email);
      return res.status(403).json({ error: 'Only super admins can modify admin status' });
    }
    
    // Don't allow deactivating yourself
    if (adminId === req.admin.id) {
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

// Delete admin (super admin only) - Only if under 3 admins
app.delete('/api/admin/:adminId', authenticateAdmin, async (req, res) => {
  const { adminId } = req.params;
  
  try {
    // Check if requesting admin is super admin
    if (req.admin.role !== 'super_admin') {
      console.log('❌ Unauthorized attempt to delete admin by:', req.admin.email);
      return res.status(403).json({ error: 'Only super admins can delete admins' });
    }
    
    // Don't allow deleting yourself
    if (adminId === req.admin.id) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }
    
    // Check if we have at least 2 admins (can't delete the last one)
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

// Admin dashboard statistics
app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
  try {
    // Get system statistics
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
        COALESCE(SUM(stake), 0) as total_wagered
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

// ==================== ADMIN AVIATOR CONTROL ENDPOINTS ====================

// Get current game settings
app.get('/api/admin/aviator/settings', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM game_settings WHERE game = 'aviator' LIMIT 1`
    );
    
    if (result.rows.length === 0) {
      // Return default settings if none exist
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

// Update game settings
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
    // Validate settings
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
    
    // If no settings exist, insert new ones
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

// Rotate game seed (provably fair)
app.post('/api/admin/aviator/rotate-seed', authenticateAdmin, async (req, res) => {
  try {
    // Generate new seed
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
      // Insert if not exists
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

// Force crash the current round
app.post('/api/admin/aviator/force-crash', authenticateAdmin, async (req, res) => {
  const { multiplier, reason } = req.body;
  
  try {
    // Check if there's an active round
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
    
    // Set crash multiplier (default to 1.01 if not specified)
    const crashMultiplier = multiplier || 1.01;
    
    // Update the round
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
    
    // Settle all pending bets for this round
    const pendingBets = await pool.query(
      `SELECT * FROM bets 
       WHERE game_type = 'aviator' 
       AND round_id = $1 
       AND status = 'pending'`,
      [round.id]
    );
    
    // Process each bet as lost (unless cashed out already)
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

// Get active round details
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
    
    // Get current participants
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

// Get round history with filters
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
    
    // Get total count
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

// Get detailed round information
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
    
    // Get all bets for this round
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
    
    // Calculate statistics
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

// Get game statistics
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
    // Overall statistics
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
    
    // Hourly breakdown for the period
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
    
    // Top players
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
    
    // Crash point distribution
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
    
    // House profit calculation
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

// Get active players
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

// Set auto crash queue
app.post('/api/admin/aviator/auto-crash-queue', authenticateAdmin, async (req, res) => {
  const { multipliers } = req.body;
  
  try {
    // Validate multipliers
    if (!Array.isArray(multipliers)) {
      return res.status(400).json({ error: 'Multipliers must be an array' });
    }
    
    for (const m of multipliers) {
      if (m < 1.01) {
        return res.status(400).json({ error: 'All multipliers must be at least 1.01' });
      }
    }
    
    // Store in database or Redis
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

// Clear auto crash queue
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

// Suspend/ban user from Aviator
app.post('/api/admin/aviator/suspend-user', authenticateAdmin, async (req, res) => {
  const { userId, reason, duration } = req.body;
  
  try {
    // Check if user exists
    const user = await pool.query(
      'SELECT id, full_name FROM profiles WHERE id = $1',
      [userId]
    );
    
    if (user.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const expiresAt = duration ? new Date(Date.now() + duration * 60 * 1000) : null;
    
    // Create suspension record
    await pool.query(
      `INSERT INTO game_suspensions (
        user_id, game, reason, suspended_by, expires_at, created_at
      ) VALUES ($1, 'aviator', $2, $3, $4, NOW())`,
      [userId, reason, req.admin.id, expiresAt]
    );
    
    // Cancel any pending bets
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

// Get suspended users
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

// Remove user suspension
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

// Get provably fair verification
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
    
    // Verify crash point using provably fair algorithm
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

// Helper function for provably fair verification
function verifyCrashPoint(serverSeed, clientSeed, nonce, actualCrashPoint) {
  // This is a simplified example - implement actual provably fair algorithm
  try {
    const hmac = crypto.createHmac('sha256', serverSeed);
    hmac.update(`${clientSeed}:${nonce}`);
    const hash = hmac.digest('hex');
    
    // Convert hash to number between 0 and 1
    const hex = hash.substring(0, 13);
    const int = parseInt(hex, 16);
    const float = int / Math.pow(16, 13);
    
    // Calculate crash point (house edge applied)
    const houseEdge = 0.03; // 3% house edge
    const crashPoint = Math.max(1, 0.99 / (1 - float) + 0.01);
    
    // Round to 2 decimal places
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

// Export game data
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
      // Convert to CSV
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

// ==================== AUTHENTICATION ENDPOINTS ====================

// Register new user
app.post('/api/register', async (req, res) => {
  const { name, email, phone, password, age } = req.body;
  
  try {
    console.log('📝 Registration attempt for:', email);
    
    // Validate required fields
    if (!name || !email || !phone || !password || !age) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    // Normalize phone number for storage
    const normalizedPhone = normalizePhoneForDatabase(phone);
    console.log('📱 Normalized phone for storage:', normalizedPhone);
    
    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT id FROM profiles WHERE phone = $1 OR email = $2',
      [normalizedPhone, email]
    );
    
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'User with this phone or email already exists' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Start transaction
    await pool.query('BEGIN');
    
    // Create user
    const userResult = await pool.query(
      `INSERT INTO profiles (phone, full_name, email, age, referral_code, password_hash) 
       VALUES ($1, $2, $3, $4, $5, $6) 
       RETURNING id, phone, full_name, email, age, referral_code, created_at`,
      [normalizedPhone, name, email, age, generateReferralCode(), hashedPassword]
    );
    
    const userId = userResult.rows[0].id;
    
    // Create wallet with welcome bonus
    await pool.query(
      `INSERT INTO wallets (user_id, main_balance, bonus_balance) 
       VALUES ($1, 100, 0)`,
      [userId]
    );
    
    // Create welcome bonus transaction
    await pool.query(
      `INSERT INTO transactions (user_id, type, amount, status, description, reference, balance_before, balance_after)
       VALUES ($1, 'bonus', 100, 'completed', 'Welcome Bonus', $2, 0, 100)`,
      [userId, 'BONUS-' + Date.now()]
    );
    
    await pool.query('COMMIT');
    
    // Generate JWT
    const expiresIn = process.env.JWT_EXPIRES_IN || '7d';
    console.log('🔑 Using expiration for registration:', expiresIn);
    console.log('🔑 User ID from database:', userId);
    
    const token = jwt.sign(
      { 
        userId: userId,
        phone: normalizedPhone, 
        email: email 
      }, 
      process.env.JWT_SECRET, 
      { expiresIn: expiresIn }
    );
    
    console.log('✅ Token generated for registration');
    console.log('🔑 Token preview:', token.substring(0, 30) + '...');
    
    // Decode to verify expiration
    const decoded = jwt.decode(token);
    console.log('📦 Token expires at:', new Date(decoded.exp * 1000).toLocaleString());
    
    console.log('✅ User registered successfully:', userId);
    
    res.json({ 
      success: true, 
      token,
      user: userResult.rows[0]
    });
    
  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('❌ Registration error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { phone, password } = req.body;
  
  try {
    console.log('🔐 Login attempt for:', phone);
    
    // Normalize phone for lookup
    const normalizedPhone = normalizePhoneForDatabase(phone);
    console.log('📱 Normalized phone for lookup:', normalizedPhone);
    
    // Get user
    const userResult = await pool.query(
      `SELECT p.*, w.main_balance, w.bonus_balance, w.affiliate_balance 
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
    
    // Verify password
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      console.log('❌ Invalid password for:', normalizedPhone);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Update last login
    await pool.query(
      'UPDATE profiles SET last_login_at = NOW(), last_login_ip = $1 WHERE id = $2',
      [req.ip || req.connection.remoteAddress, user.id]
    );
    
    // Generate JWT
    const expiresIn = process.env.JWT_EXPIRES_IN || '7d';
    console.log('🔑 JWT_EXPIRES_IN from env:', expiresIn);
    console.log('🔑 User ID from database:', user.id);
    
    const token = jwt.sign(
      { 
        userId: user.id,
        phone: user.phone, 
        email: user.email 
      }, 
      process.env.JWT_SECRET, 
      { expiresIn: expiresIn }
    );
    
    console.log('✅ Token generated with expiration:', expiresIn);
    console.log('🔑 Token preview:', token.substring(0, 30) + '...');
    console.log('🔑 Token length:', token.length);
    
    // Decode to verify expiration
    const decoded = jwt.decode(token);
    const expiresAt = new Date(decoded.exp * 1000);
    const now = new Date();
    const expiresInMs = expiresAt.getTime() - now.getTime();
    const expiresInHours = expiresInMs / (1000 * 60 * 60);
    
    console.log('📦 Current time:', now.toLocaleString());
    console.log('📦 Token expires at:', expiresAt.toLocaleString());
    console.log('📦 Token expires in:', expiresInHours.toFixed(2), 'hours');
    
    // Verify the token immediately to ensure it's valid
    try {
      jwt.verify(token, process.env.JWT_SECRET);
      console.log('✅ Token verification passed immediately after creation');
    } catch (verifyError) {
      console.error('❌ Token verification failed immediately:', verifyError.message);
    }
    
    console.log('✅ Login successful for:', user.id);
    
    // Calculate total balance
    const mainBalance = parseFloat(user.main_balance || 0);
    const bonusBalance = parseFloat(user.bonus_balance || 0);
    const affiliateBalance = parseFloat(user.affiliate_balance || 0);
    
    // Don't send password_hash back
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
        total_balance: (mainBalance + bonusBalance + affiliateBalance).toFixed(2)
      }
    });
    
  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== PROFILE ENDPOINTS ====================

// Get user profile
app.get('/api/profile/:userId', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.id, p.phone, p.full_name, p.email, p.age, p.referral_code, 
              p.kyc_status, p.is_verified, p.avatar_url, p.city, p.date_of_birth,
              p.created_at, p.updated_at,
              w.main_balance, w.bonus_balance, w.affiliate_balance, w.total_balance,
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

// Update profile
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

// ==================== PROFILE IMAGE ENDPOINTS ====================

// Upload profile image
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

// Remove profile image
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

// ==================== WALLET ENDPOINTS ====================

// Get wallet balance
app.get('/api/wallet/:userId', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM wallets WHERE user_id = $1`,
      [req.params.userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Wallet not found' });
    }
    
    res.json(result.rows[0]);
    
  } catch (error) {
    console.error('Wallet error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get transaction history
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
    // Check if token is still valid
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

// ==================== M-PESA STK PUSH ====================
app.post('/api/mpesa/stkpush', authenticateToken, async (req, res) => {
  const { userId, phoneNumber, amount } = req.body;
  
  try {
    console.log('📱 ===== M-PESA STK PUSH INITIATED =====');
    console.log('📱 User ID from request:', userId);
    console.log('📱 Phone:', phoneNumber);
    console.log('📱 Amount:', amount);

    // Validate amount
    if (amount < 10 || amount > 70000) {
      return res.status(400).json({ 
        success: false, 
        error: 'Amount must be between KES 10 and 70,000' 
      });
    }

    // Format phone number
    let formattedPhone = formatPhoneForMPesa(phoneNumber);
    console.log('📱 Formatted phone for M-PESA:', formattedPhone);
    
    if (formattedPhone.length !== 12) {
      return res.status(400).json({
        success: false,
        error: 'Invalid phone number format. Use 07XXXXXXXX or 2547XXXXXXXX'
      });
    }

    console.log('🔍 Looking up user by phone number:', formattedPhone);
    
    // Find user by phone
    const userByPhone = await pool.query(
      'SELECT id, phone, full_name FROM profiles WHERE phone = $1',
      [formattedPhone]
    );
    
    let dbUserId;
    
    if (userByPhone.rows.length > 0) {
      dbUserId = userByPhone.rows[0].id;
      console.log('✅ Found user by phone:');
      console.log('   - ID:', dbUserId);
      console.log('   - Phone:', userByPhone.rows[0].phone);
      console.log('   - Name:', userByPhone.rows[0].full_name);
    } else {
      console.log('❌ User not found with phone:', formattedPhone);
      
      const originalPhoneSearch = await pool.query(
        'SELECT id, phone, full_name FROM profiles WHERE phone = $1',
        [phoneNumber]
      );
      
      if (originalPhoneSearch.rows.length > 0) {
        dbUserId = originalPhoneSearch.rows[0].id;
        console.log('✅ Found user by original phone:');
        console.log('   - ID:', dbUserId);
        console.log('   - Phone:', originalPhoneSearch.rows[0].phone);
      } else {
        console.error('❌ User NOT FOUND with any phone format');
        
        const sampleUsers = await pool.query(
          'SELECT id, phone, full_name FROM profiles LIMIT 5'
        );
        console.log('📋 Sample users in database:');
        sampleUsers.rows.forEach(user => {
          console.log(`   - ID: ${user.id}, Phone: ${user.phone}, Name: ${user.full_name}`);
        });
        
        return res.status(400).json({ 
          success: false, 
          error: 'User account not found. Please login again.' 
        });
      }
    }

    const token = await getMpesaToken();
    console.log('✅ Token obtained');

    const date = new Date();
    const timestamp = date.getFullYear() +
      String(date.getMonth() + 1).padStart(2, '0') +
      String(date.getDate()).padStart(2, '0') +
      String(date.getHours()).padStart(2, '0') +
      String(date.getMinutes()).padStart(2, '0') +
      String(date.getSeconds()).padStart(2, '0');
    
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

    console.log('📤 Sending STK Push request to Safaricom...');

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
        user_id,
        phone_number,
        amount,
        reference,
        checkout_request_id,
        merchant_request_id,
        type,
        payment_type,
        status,
        result_code,
        result_description,
        customer_message,
        created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())
      RETURNING id`,
      [
        dbUserId,
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

    console.log('✅ Transaction inserted with ID:', result.rows[0].id);

    if (ResponseCode === '0') {
      res.json({ 
        success: true, 
        message: CustomerMessage || 'STK Push sent. Please check your phone to complete payment.',
        transactionId: result.rows[0].id,
        checkoutRequestId: CheckoutRequestID,
        reference
      });
    } else {
      res.status(400).json({ 
        success: false, 
        error: ResponseDescription || 'Failed to initiate STK Push'
      });
    }
    
  } catch (error) {
    console.error('❌ STK Push error:', error);
    
    if (error.code === '23503') {
      console.error('❌ Foreign key violation - user_id does not exist in profiles table');
      return res.status(400).json({ 
        success: false, 
        error: 'User account issue. Please try logging in again.' 
      });
    }
    
    res.status(500).json({ 
      success: false, 
      error: 'Failed to initiate payment. Please try again.'
    });
  }
});

// ==================== M-PESA CALLBACK ====================
app.post('/api/mpesa/callback', async (req, res) => {
  console.log('📞 ===== M-PESA CALLBACK RECEIVED =====');
  console.log('📞 Timestamp:', new Date().toISOString());
  console.log('📞 Headers:', JSON.stringify(req.headers, null, 2));
  console.log('📞 Callback body:', JSON.stringify(req.body, null, 2));
  
  // Always acknowledge immediately
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

    const transaction = await client.query(
      `SELECT * FROM mpesa_transactions 
       WHERE checkout_request_id = $1 
       FOR UPDATE`,
      [CheckoutRequestID]
    );
    
    if (transaction.rows.length === 0) {
      console.log('❌ Transaction not found for CheckoutRequestID:', CheckoutRequestID);
      await client.query('ROLLBACK');
      client.release();
      return;
    }

    const tx = transaction.rows[0];
    
    if (tx.status !== 'pending') {
      console.log(`⚠️ Transaction already processed with status: ${tx.status}`);
      await client.query('ROLLBACK');
      client.release();
      return;
    }

    console.log('📞 Found transaction:', tx.id, 'for user:', tx.user_id);

    if (ResultCode === 0) {
      let amount = tx.amount;
      let receipt = '';
      let phoneNumber = '';
      
      if (CallbackMetadata?.Item) {
        CallbackMetadata.Item.forEach(item => {
          if (item.Name === 'Amount') amount = item.Value;
          if (item.Name === 'MpesaReceiptNumber') receipt = item.Value;
          if (item.Name === 'PhoneNumber') phoneNumber = item.Value;
        });
      }

      await client.query(
        `UPDATE mpesa_transactions 
         SET status = 'completed', 
             mpesa_receipt_number = $1,
             result_code = $2,
             result_description = $3,
             completed_at = NOW(),
             updated_at = NOW()
         WHERE id = $4`,
        [receipt, ResultCode, ResultDesc, tx.id]
      );

      let walletResult = await client.query(
        `SELECT * FROM wallets 
         WHERE user_id = $1 
         FOR UPDATE`,
        [tx.user_id]
      );
      
      let currentBalance = 0;
      
      if (walletResult.rows.length === 0) {
        const newWallet = await client.query(
          `INSERT INTO wallets (user_id, main_balance, bonus_balance, affiliate_balance, lifetime_deposits)
           VALUES ($1, 0, 0, 0, 0)
           RETURNING *`,
          [tx.user_id]
        );
        currentBalance = parseFloat(newWallet.rows[0].main_balance);
      } else {
        currentBalance = parseFloat(walletResult.rows[0].main_balance);
      }

      await client.query(
        `UPDATE wallets 
         SET main_balance = main_balance + $1,
             lifetime_deposits = lifetime_deposits + $1,
             updated_at = NOW()
         WHERE user_id = $2`,
        [amount, tx.user_id]
      );

      const transactionResult = await client.query(
        `INSERT INTO transactions 
         (user_id, type, amount, status, description, reference, balance_before, balance_after, created_at)
         VALUES ($1, 'deposit', $2, 'completed', $3, $4, $5, $5 + $2, NOW())
         RETURNING id`,
        [tx.user_id, amount, `M-PESA deposit (Receipt: ${receipt})`, tx.reference, currentBalance]
      );

      await client.query('COMMIT');
      
      console.log(`✅✅✅ SUCCESS: Wallet updated for user ${tx.user_id}: +KES ${amount} (Receipt: ${receipt})`);
      console.log(`📝 New balance: ${currentBalance + amount}, Transaction ID: ${transactionResult.rows[0].id}`);
      
    } else {
      console.log(`❌ Payment failed: ${ResultDesc}`);
      
      await client.query(
        `UPDATE mpesa_transactions 
         SET status = 'failed',
             result_code = $1,
             result_description = $2,
             updated_at = NOW()
         WHERE id = $3`,
        [ResultCode, ResultDesc, tx.id]
      );

      await client.query('COMMIT');
      console.log(`✅ Transaction ${tx.id} marked as failed`);
    }
    
  } catch (error) {
    console.error('❌❌❌ Callback error:', error);
    if (client) {
      await client.query('ROLLBACK').catch(e => {});
    }
  } finally {
    if (client) {
      client.release();
    }
  }
});

// ==================== RECOVERY ENDPOINT ====================
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
        const timestamp = date.getFullYear() +
          String(date.getMonth() + 1).padStart(2, '0') +
          String(date.getDate()).padStart(2, '0') +
          String(date.getHours()).padStart(2, '0') +
          String(date.getMinutes()).padStart(2, '0') +
          String(date.getSeconds()).padStart(2, '0');
        
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
             (user_id, type, amount, status, description, reference, balance_before, balance_after)
             VALUES ($1, 'deposit', $2, 'completed', $3, $4, $5, $5 + $2)`,
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

// ==================== QUERY STK PUSH STATUS ====================
app.post('/api/mpesa/query', authenticateToken, async (req, res) => {
  const { checkoutRequestId } = req.body;
  
  try {
    const token = await getMpesaToken();
    
    const date = new Date();
    const timestamp = `${date.getFullYear()}${String(date.getMonth() + 1).padStart(2, '0')}${String(date.getDate()).padStart(2, '0')}${String(date.getHours()).padStart(2, '0')}${String(date.getMinutes()).padStart(2, '0')}${String(date.getSeconds()).padStart(2, '0')}`;
    
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

// ==================== FORGOT PASSWORD / RESET PASSWORD ====================

// Reset password endpoint
app.post('/api/reset-password', async (req, res) => {
  const { phone, newPassword } = req.body;
  
  try {
    console.log('🔐 Password reset attempt for phone:', phone);
    
    if (!phone || !newPassword) {
      return res.status(400).json({ error: 'Phone and new password are required' });
    }
    
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    let formattedPhone = normalizePhoneForDatabase(phone);
    console.log('📱 Formatted phone for lookup:', formattedPhone);
    
    const userResult = await pool.query(
      'SELECT id, full_name, phone FROM profiles WHERE phone = $1',
      [formattedPhone]
    );
    
    if (userResult.rows.length === 0) {
      console.log('❌ User not found with phone:', formattedPhone);
      return res.status(404).json({ error: 'User not found with this phone number' });
    }
    
    const user = userResult.rows[0];
    console.log('✅ User found:', user.id, user.full_name);
    
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

// ==================== CHECK PAYMENT STATUS ====================
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

// ==================== WITHDRAWAL ENDPOINT ====================
app.post('/api/withdraw', authenticateToken, async (req, res) => {
  const { userId, phoneNumber, amount, method } = req.body;
  
  let client;
  
  try {
    console.log('📤 Withdrawal initiated:', { userId, phoneNumber, amount, method });
    
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
    
    const currentBalance = parseFloat(walletResult.rows[0].main_balance);
    
    if (currentBalance < amount) {
      await client.query('ROLLBACK');
      client.release();
      return res.status(400).json({ 
        error: 'Insufficient balance',
        available: currentBalance,
        requested: amount
      });
    }
    
    if (amount < 50) {
      await client.query('ROLLBACK');
      client.release();
      return res.status(400).json({ error: 'Minimum withdrawal is KES 50' });
    }
    
    const formattedPhone = formatPhoneForMPesa(phoneNumber);
    
    const reference = 'WDR' + Date.now().toString().slice(-8) + Math.random().toString(36).substring(2, 5).toUpperCase();
    
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
           lifetime_withdrawals = lifetime_withdrawals + $1,
           updated_at = NOW()
       WHERE user_id = $2`,
      [amount, userId]
    );
    
    await client.query(
      `INSERT INTO transactions 
       (user_id, type, amount, status, description, reference, method, balance_before, balance_after, created_at)
       VALUES ($1, 'withdrawal', $2, 'pending', $3, $4, $5, $6, $6 - $2, NOW())`,
      [userId, amount, `Withdrawal via ${method}`, reference, method, currentBalance]
    );
    
    await client.query('COMMIT');
    
    processWithdrawal(withdrawalResult.rows[0].id, userId, amount, formattedPhone, reference).catch(err => {
      console.error('Background withdrawal error:', err);
    });
    
    res.json({ 
      success: true, 
      message: 'Withdrawal initiated successfully',
      transactionId: withdrawalResult.rows[0].id,
      reference
    });
    
  } catch (error) {
    if (client) {
      await client.query('ROLLBACK');
      client.release();
    }
    console.error('❌ Withdrawal error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Background withdrawal processor
async function processWithdrawal(transactionId, userId, amount, phoneNumber, reference) {
  let client;
  
  try {
    console.log(`🔄 Processing withdrawal ${transactionId} for user ${userId}`);
    
    await new Promise(resolve => setTimeout(resolve, 5000));
    
    client = await pool.connect();
    await client.query('BEGIN');
    
    const receipt = 'WDR' + Date.now().toString().slice(-10);
    
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
    
    console.log(`✅ Withdrawal ${transactionId} completed: KES ${amount} to ${phoneNumber}`);
    
  } catch (error) {
    console.error(`❌ Withdrawal processing error for ${transactionId}:`, error);
    
    if (client) {
      try {
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
        
        await client.query('COMMIT');
      } catch (refundError) {
        console.error('❌ Refund failed:', refundError);
      }
    }
  } finally {
    if (client) client.release();
  }
}

// ==================== FIXED BETTING ENDPOINTS ====================

// Place a bet
app.post('/api/bets', authenticateToken, async (req, res) => {
  const { userId, selections, stake, totalOdds, potentialWinnings } = req.body;
  
  let client;
  
  try {
    console.log('🎲 Bet placement:', { userId, stake, selections: selections.length });
    
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
    
    const currentBalance = parseFloat(walletResult.rows[0].main_balance);
    
    if (currentBalance < stake) {
      await client.query('ROLLBACK');
      client.release();
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    const referenceNumber = 'BET-' + Date.now() + '-' + Math.random().toString(36).substring(2, 8).toUpperCase();
    
    const betResult = await client.query(
      `INSERT INTO bets (
        user_id, 
        selections, 
        stake, 
        total_odds, 
        potential_winnings, 
        bet_type,
        reference_number,
        status
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
      [
        userId, 
        JSON.stringify(selections), 
        stake, 
        totalOdds, 
        potentialWinnings, 
        selections.length > 1 ? 'accumulator' : 'single',
        referenceNumber,
        'pending'
      ]
    );
    
    await client.query(
      `UPDATE wallets 
       SET main_balance = main_balance - $1,
           lifetime_bets = lifetime_bets + $1,
           updated_at = NOW()
       WHERE user_id = $2`,
      [stake, userId]
    );
    
    await client.query(
      `INSERT INTO transactions (
        user_id, 
        type, 
        amount, 
        status, 
        description, 
        reference, 
        balance_before, 
        balance_after
      ) VALUES ($1, 'bet', $2, 'completed', 'Bet placed', $3, $4, $4 - $2)`,
      [userId, stake, referenceNumber, currentBalance]
    );
    
    await client.query('COMMIT');
    
    res.json({ 
      success: true, 
      betId: betResult.rows[0].id,
      message: 'Bet placed successfully'
    });
    
  } catch (error) {
    if (client) {
      await client.query('ROLLBACK');
      client.release();
    }
    console.error('❌ Bet error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get user's bets
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

// Cancel a pending bet
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
      client.release();
      return res.status(400).json({ error: 'Bet not found or cannot be cancelled' });
    }
    
    const bet = betResult.rows[0];
    
    await client.query(
      'UPDATE bets SET status = $1, updated_at = NOW() WHERE id = $2',
      ['cancelled', betId]
    );
    
    const walletResult = await client.query(
      'SELECT main_balance FROM wallets WHERE user_id = $1 FOR UPDATE',
      [userId]
    );
    
    const currentBalance = parseFloat(walletResult.rows[0].main_balance);
    
    await client.query(
      `UPDATE wallets 
       SET main_balance = main_balance + $1,
           updated_at = NOW()
       WHERE user_id = $2`,
      [bet.stake, userId]
    );
    
    await client.query(
      `INSERT INTO transactions (user_id, type, amount, status, description, reference, balance_before, balance_after)
       VALUES ($1, 'adjustment', $2, 'completed', 'Bet cancellation refund', $3, $4, $4 + $2)`,
      [userId, bet.stake, 'REF-' + Date.now(), currentBalance]
    );
    
    await client.query('COMMIT');
    
    res.json({ success: true, message: 'Bet cancelled and stake refunded' });
    
  } catch (error) {
    if (client) {
      await client.query('ROLLBACK');
      client.release();
    }
    console.error('❌ Cancel bet error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== FIXED BONUS ENDPOINTS ====================

// Get user bonuses
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

// Claim welcome bonus
app.post('/api/bonuses/welcome/claim', authenticateToken, async (req, res) => {
  const { userId } = req.body;
  
  let client;
  
  try {
    // Check if already claimed
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
      'SELECT main_balance FROM wallets WHERE user_id = $1 FOR UPDATE',
      [userId]
    );
    
    const currentBalance = parseFloat(walletResult.rows[0]?.main_balance || 0);
    
    await client.query(
      `INSERT INTO user_bonuses (user_id, bonus_id, amount, status, claimed_at)
       VALUES ($1, $2, $3, 'completed', NOW())`,
      [userId, bonus.id, bonus.amount]
    );
    
    await client.query(
      `UPDATE wallets 
       SET main_balance = main_balance + $1,
           updated_at = NOW()
       WHERE user_id = $2`,
      [bonus.amount, userId]
    );
    
    await client.query(
      `INSERT INTO transactions (user_id, type, amount, status, description, reference, balance_before, balance_after)
       VALUES ($1, 'bonus', $2, 'completed', 'Welcome bonus claimed', $3, $4, $4 + $2)`,
      [userId, bonus.amount, 'BONUS-' + Date.now(), currentBalance]
    );
    
    await client.query('COMMIT');
    
    res.json({ 
      success: true, 
      message: 'Welcome bonus claimed successfully',
      amount: bonus.amount
    });
    
  } catch (error) {
    if (client) {
      await client.query('ROLLBACK');
      client.release();
    }
    console.error('❌ Claim bonus error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== GAME BETTING ENDPOINTS ====================

// Place a game bet (Aviator/JetX)
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
    
    client = await pool.connect();
    await client.query('BEGIN');
    
    const wallet = await client.query(
      'SELECT main_balance FROM wallets WHERE user_id = $1 FOR UPDATE',
      [userId]
    );
    
    if (wallet.rows.length === 0) {
      await client.query('ROLLBACK');
      client.release();
      return res.status(404).json({ error: 'Wallet not found' });
    }
    
    const currentBalance = parseFloat(wallet.rows[0].main_balance);
    
    if (currentBalance < stake) {
      await client.query('ROLLBACK');
      client.release();
      return res.status(400).json({ 
        error: 'Insufficient balance',
        available: currentBalance,
        required: stake
      });
    }
    
    let roundResult = await client.query(
      `SELECT * FROM game_rounds 
       WHERE game = $1 AND status = 'flying' 
       ORDER BY created_at DESC 
       LIMIT 1`,
      [gameType]
    );
    
    let roundId;
    
    if (roundResult.rows.length === 0) {
      const newRound = await client.query(
        `INSERT INTO game_rounds (game, round_number, status, started_at)
         VALUES ($1, COALESCE((SELECT MAX(round_number) + 1 FROM game_rounds WHERE game = $1), 1), 'flying', NOW())
         RETURNING id`,
        [gameType]
      );
      roundId = newRound.rows[0].id;
    } else {
      roundId = roundResult.rows[0].id;
    }
    
    const betResult = await client.query(
      `INSERT INTO bets (
        user_id, 
        selections, 
        stake, 
        total_odds, 
        potential_winnings,
        status, 
        bet_type, 
        game_type,
        round_id,
        reference_number,
        created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
      RETURNING id`,
      [
        userId,
        JSON.stringify([{ game: gameType, multiplier: 1.0 }]),
        stake,
        1.0,
        stake * (autoCashout || 1.0),
        'pending',
        'single',
        gameType,
        roundId,
        `${gameType}-${Date.now()}-${Math.floor(Math.random() * 1000)}`
      ]
    );
    
    const betId = betResult.rows[0].id;
    
    await client.query(
      `UPDATE wallets 
       SET main_balance = main_balance - $1,
           lifetime_bets = lifetime_bets + $1,
           updated_at = NOW()
       WHERE user_id = $2`,
      [stake, userId]
    );
    
    await client.query(
      `INSERT INTO transactions (
        user_id, type, amount, status, description, 
        reference, balance_before, balance_after
      ) VALUES ($1, 'bet', $2, 'completed', $3, $4, $5, $5 - $2)`,
      [
        userId,
        stake,
        `${gameType} bet placed`,
        `BET-${betId}`,
        currentBalance,
        currentBalance - stake
      ]
    );
    
    await client.query('COMMIT');
    
    console.log(`✅ Bet placed: User ${userId} bet KES ${stake} on ${gameType}`);
    
    res.json({
      success: true,
      betId,
      roundId,
      message: 'Bet placed successfully',
      newBalance: currentBalance - stake
    });
    
  } catch (error) {
    if (client) {
      await client.query('ROLLBACK');
      client.release();
    }
    console.error('❌ Game bet error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Cashout from game
app.post('/api/games/cashout', authenticateToken, async (req, res) => {
  const { betId, userId, multiplier } = req.body;
  
  let client;
  
  try {
    console.log('💰 Processing cashout:', { betId, userId, multiplier });
    
    if (req.user.userId !== userId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    client = await pool.connect();
    await client.query('BEGIN');
    
    const bet = await client.query(
      'SELECT * FROM bets WHERE id = $1 AND user_id = $2 AND status = $3 FOR UPDATE',
      [betId, userId, 'pending']
    );
    
    if (bet.rows.length === 0) {
      await client.query('ROLLBACK');
      client.release();
      return res.status(404).json({ error: 'Bet not found or already settled' });
    }
    
    const betData = bet.rows[0];
    const winAmount = parseFloat(betData.stake) * multiplier;
    
    await client.query(
      `UPDATE bets 
       SET status = 'cashed_out', 
           cashout_multiplier = $1,
           actual_winnings = $2,
           settled_at = NOW()
       WHERE id = $3`,
      [multiplier, winAmount, betId]
    );
    
    const wallet = await client.query(
      'SELECT main_balance FROM wallets WHERE user_id = $1 FOR UPDATE',
      [userId]
    );
    
    const currentBalance = parseFloat(wallet.rows[0].main_balance);
    
    await client.query(
      `UPDATE wallets 
       SET main_balance = main_balance + $1,
           lifetime_winnings = lifetime_winnings + $1,
           updated_at = NOW()
       WHERE user_id = $2`,
      [winAmount, userId]
    );
    
    await client.query(
      `INSERT INTO transactions (
        user_id, type, amount, status, description, 
        reference, balance_before, balance_after
      ) VALUES ($1, 'win', $2, 'completed', $3, $4, $5, $5 + $2)`,
      [
        userId,
        winAmount,
        `Cashed out at ${multiplier}x`,
        `WIN-${betId}`,
        currentBalance,
        currentBalance + winAmount
      ]
    );
    
    await client.query('COMMIT');
    
    console.log(`✅ Cashout processed: User ${userId} won KES ${winAmount} at ${multiplier}x`);
    
    res.json({
      success: true,
      winAmount,
      message: `Cashed out at ${multiplier}x! You won KES ${winAmount}`,
      newBalance: currentBalance + winAmount
    });
    
  } catch (error) {
    if (client) {
      await client.query('ROLLBACK');
      client.release();
    }
    console.error('❌ Cashout error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/games/history/:gameType', async (req, res) => {
  const { gameType } = req.params;
  const limit = parseInt(req.query.limit) || 20;
  
  try {
    const history = await pool.query(
      `SELECT round_number, crash_point, created_at 
       FROM game_rounds 
       WHERE game = $1 AND status = 'completed'
       ORDER BY created_at DESC
       LIMIT $2`,
      [gameType, limit]
    );
    
    res.json(history.rows);
    
  } catch (error) {
    console.error('❌ Game history error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== FAQ ENDPOINT ====================

// Get FAQs
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
      },
      {
        id: '5',
        category: 'Deposits & Withdrawals',
        categoryIcon: '💰',
        question: 'What are the withdrawal limits?',
        answer: 'Minimum withdrawal: KES 100. Maximum per transaction: KES 70,000. Daily limit: KES 140,000.'
      },
      {
        id: '6',
        category: 'Betting Guide',
        categoryIcon: '⚽',
        question: 'How do I place a bet?',
        answer: 'Select a match → Choose odds → Add to bet slip → Enter stake → Confirm. Minimum stake is KES 10.'
      },
      {
        id: '7',
        category: 'Betting Guide',
        categoryIcon: '⚽',
        question: 'What is an accumulator?',
        answer: 'An accumulator combines multiple selections into one bet. All selections must win for you to win.'
      },
      {
        id: '8',
        category: 'Betting Guide',
        categoryIcon: '⚽',
        question: 'How are winnings calculated?',
        answer: 'Winnings = Stake × (Odds1 × Odds2 × ...). Example: KES 100 stake at odds 2.0 = KES 200 return.'
      },
      {
        id: '9',
        category: 'Bonuses & Promotions',
        categoryIcon: '🎁',
        question: 'How do I claim the welcome bonus?',
        answer: 'Make your first deposit of at least KES 100. The 100% bonus up to KES 10,000 is automatically credited.'
      },
      {
        id: '10',
        category: 'Bonuses & Promotions',
        categoryIcon: '🎁',
        question: 'How do I unlock my bonus?',
        answer: 'Place 5 bets with odds ≥ 1.8, total stake ≥ KES 5,000. Progress shows in your Bonus section.'
      },
      {
        id: '11',
        category: 'Affiliate Program',
        categoryIcon: '🤝',
        question: 'How does the affiliate program work?',
        answer: 'Share your referral code. Earn 10% commission on deposits from users who sign up with your code.'
      },
      {
        id: '12',
        category: 'Affiliate Program',
        categoryIcon: '🤝',
        question: 'When do I get paid?',
        answer: 'Affiliate earnings are updated in real-time and can be withdrawn anytime from your Affiliate wallet.'
      },
      {
        id: '13',
        category: 'Account Security',
        categoryIcon: '🔒',
        question: 'How do I change my password?',
        answer: 'Go to Profile → Settings → Change Password. You\'ll need your current password.'
      },
      {
        id: '14',
        category: 'Account Security',
        categoryIcon: '🔒',
        question: 'What if I forget my password?',
        answer: 'Click "Forgot Password" on login. Enter your phone to receive OTP and reset password.'
      }
    ];
    
    res.json(faqs);
  } catch (error) {
    console.error('❌ FAQs error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get contact information
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

// Submit feedback
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

// Get support statistics
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

// ==================== LEAGUES AND MATCHES ====================

// Get all leagues
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

// Get upcoming matches
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

// Get live matches
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

// Get matches by league
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

// Get match details
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

// ==================== STATISTICS ENDPOINTS ====================

// Get user statistics
app.get('/api/stats/:userId', authenticateToken, async (req, res) => {
  try {
    const betsResult = await pool.query(
      'SELECT COUNT(*) as total_bets FROM bets WHERE user_id = $1',
      [req.params.userId]
    );
    
    const winsResult = await pool.query(
      'SELECT COUNT(*) as wins FROM bets WHERE user_id = $1 AND status = $2',
      [req.params.userId, 'won']
    );
    
    res.json({
      total_bets: parseInt(betsResult.rows[0].total_bets),
      wins: parseInt(winsResult.rows[0].wins),
      losses: 0,
      win_rate: 0
    });
  } catch (error) {
    console.error('❌ Stats error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== ERROR HANDLING MIDDLEWARE ====================
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// 404 handler
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
  console.log(`   👤 GET  /api/profile/:userId`);
  console.log(`   👤 POST /api/profile/upload-image`);
  console.log(`   👤 POST /api/profile/remove-image`);
  console.log(`   💰 GET  /api/wallet/:userId`);
  console.log(`   💳 GET  /api/transactions/:userId`);
  console.log(`   💸 POST /api/withdraw`);
  console.log(`   🎲 POST /api/bets`);
  console.log(`   📋 GET  /api/bets/:userId`);
  console.log(`   ❌ POST /api/bets/:betId/cancel`);
  console.log(`   🎁 GET  /api/bonuses/:userId`);
  console.log(`   🎁 POST /api/bonuses/welcome/claim`);
  console.log(`   🏆 GET  /api/jackpot/current`);
  console.log(`   🏆 POST /api/jackpot/entry`);
  console.log(`   📞 POST /api/mpesa/stkpush`);
  console.log(`   🔍 GET  /api/payment/status/:transactionId`);
  console.log(`   📞 POST /api/mpesa/callback`);
  console.log(`   🔄 POST /api/mpesa/recover-pending`);
  console.log(`   🎫 POST /api/support/tickets`);
  console.log(`   ⚽ GET  /api/leagues`);
  console.log(`   ⚽ GET  /api/matches/upcoming`);
  console.log(`   🔐 POST /api/reset-password`);
  console.log(`   🔴 GET  /api/matches/live`);
  console.log(`   📊 GET  /api/stats/:userId`);
  console.log(`   📚 GET  /api/support/faqs`);
  console.log(`   📞 GET  /api/support/contact`);
  console.log(`   📝 POST /api/support/feedback`);
  console.log(`   📊 GET  /api/support/stats`);
  console.log(`   🧪 GET  /api/test-jwt`);
  console.log(`=========================================`);
});

// Graceful shutdown
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
