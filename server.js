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

// ==================== CORS CONFIGURATION ====================
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

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps, curl, Postman)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1 || process.env.NODE_ENV !== 'production') {
      callback(null, true);
    } else {
      console.log('❌ Blocked origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
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

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

// Test database connection on startup
pool.connect((err, client, release) => {
  if (err) {
    console.error('❌ Database connection error:', err.stack);
  } else {
    console.log('✅ Database connected successfully');
    release();
  }
});

// ==================== AUTHENTICATION MIDDLEWARE ====================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error('❌ Token verification failed:', err.message);
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

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
    
    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT id FROM profiles WHERE phone = $1 OR email = $2',
      [phone, email]
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
      [phone, name, email, age, generateReferralCode(), hashedPassword]
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
    const token = jwt.sign(
      { userId, phone, email }, 
      process.env.JWT_SECRET, 
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );
    
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
    
    // Get user
    const userResult = await pool.query(
      `SELECT p.*, w.main_balance, w.bonus_balance, w.affiliate_balance 
       FROM profiles p 
       LEFT JOIN wallets w ON p.id = w.user_id 
       WHERE p.phone = $1`,
      [phone]
    );
    
    if (userResult.rows.length === 0) {
      console.log('❌ User not found:', phone);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = userResult.rows[0];
    
    // Verify password
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      console.log('❌ Invalid password for:', phone);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Update last login
    await pool.query(
      'UPDATE profiles SET last_login_at = NOW(), last_login_ip = $1 WHERE id = $2',
      [req.ip || req.connection.remoteAddress, user.id]
    );
    
    // Generate JWT
    const token = jwt.sign(
      { userId: user.id, phone: user.phone, email: user.email }, 
      process.env.JWT_SECRET, 
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );
    
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

// ==================== NEW PROFILE IMAGE ENDPOINTS ====================

// Upload profile image
app.post('/api/profile/upload-image', authenticateToken, async (req, res) => {
  const { userId, image } = req.body;
  
  try {
    console.log('📤 Uploading image for user:', userId);
    
    // In production, you'd save the image to cloud storage (S3, Cloudinary, etc.)
    // For now, store the base64 image or a reference
    await pool.query(
      'UPDATE profiles SET avatar_url = $1, updated_at = NOW() WHERE id = $2',
      [image, userId] // Store base64 or URL
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
      'SELECT * FROM wallets WHERE user_id = $1',
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

// ==================== M-PESA STK PUSH ====================
app.post('/api/mpesa/stkpush', authenticateToken, async (req, res) => {
  const { userId, phoneNumber, amount } = req.body;
  
  try {
    console.log('📱 ===== M-PESA STK PUSH INITIATED =====');
    console.log('📱 User ID:', userId);
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
    const formattedPhone = formatPhoneForMPesa(phoneNumber);
    console.log('📱 Formatted phone:', formattedPhone);

    // Generate unique reference
    const reference = 'DEP' + Date.now().toString().slice(-8);
    const checkoutRequestId = `ws_CO_${Date.now()}_${Math.random().toString(36).substring(2, 10)}`;

    // Start transaction
    await pool.query('BEGIN');

    // Create transaction record
    const mpesaResult = await pool.query(
      `INSERT INTO mpesa_transactions 
       (user_id, phone_number, amount, reference, checkout_request_id, type, payment_type, status)
       VALUES ($1, $2, $3, $4, $5, 'deposit', 'stk', 'pending')
       RETURNING id`,
      [userId, formattedPhone, amount, reference, checkoutRequestId]
    );

    // Get current balance
    const walletResult = await pool.query(
      'SELECT main_balance FROM wallets WHERE user_id = $1',
      [userId]
    );
    
    const currentBalance = parseFloat(walletResult.rows[0]?.main_balance || 0);
    console.log('💰 Current balance:', currentBalance);

    await pool.query('COMMIT');

    // Simulate payment processing after 10 seconds
    setTimeout(async () => {
      try {
        await pool.query('BEGIN');
        
        console.log('⏳ Processing payment for user:', userId);
        
        // Generate M-PESA receipt
        const mpesaReceipt = 'MP' + Date.now().toString().slice(-10);
        
        // Update M-PESA transaction
        await pool.query(
          `UPDATE mpesa_transactions 
           SET status = 'completed', 
               mpesa_receipt_number = $1,
               completed_at = NOW()
           WHERE id = $2`,
          [mpesaReceipt, mpesaResult.rows[0].id]
        );
        
        // Update wallet balance
        await pool.query(
          `UPDATE wallets 
           SET main_balance = main_balance + $1,
               lifetime_deposits = lifetime_deposits + $1,
               last_updated = NOW()
           WHERE user_id = $2`,
          [amount, userId]
        );
        
        // Create transaction record
        await pool.query(
          `INSERT INTO transactions 
           (user_id, type, amount, status, description, reference, method, payment_type, balance_before, balance_after)
           VALUES ($1, 'deposit', $2, 'completed', 'M-PESA deposit', $3, 'mpesa', 'stk', $4, $4 + $2)`,
          [userId, amount, reference, currentBalance]
        );
        
        await pool.query('COMMIT');
        console.log(`✅ Payment completed for user ${userId}: KES ${amount}`);
        console.log(`📱 M-PESA Receipt: ${mpesaReceipt}`);
        
      } catch (error) {
        await pool.query('ROLLBACK');
        console.error('❌ Payment completion error:', error);
      }
    }, 10000);

    // Return immediate response
    res.json({ 
      success: true, 
      message: 'STK Push sent. Please check your phone and enter PIN to complete payment.',
      transactionId: mpesaResult.rows[0].id,
      reference,
      checkoutRequestId
    });
    
  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('❌ STK Push error:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message,
      message: 'Failed to initiate payment. Please try again.' 
    });
  }
});

// Check payment status
app.get('/api/payment/status/:transactionId', authenticateToken, async (req, res) => {
  const { transactionId } = req.params;
  
  try {
    const result = await pool.query(
      `SELECT status, amount, mpesa_receipt_number, completed_at 
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

// M-PESA Callback
app.post('/api/mpesa/callback', async (req, res) => {
  console.log('📞 M-PESA Callback received:', JSON.stringify(req.body, null, 2));
  
  // Always acknowledge receipt
  res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
  
  try {
    const { Body } = req.body;
    if (Body && Body.stkCallback) {
      const { 
        ResultCode, 
        ResultDesc, 
        CheckoutRequestID, 
        CallbackMetadata 
      } = Body.stkCallback;
      
      if (ResultCode === 0) {
        // Payment successful
        const metadata = CallbackMetadata.Item;
        const amount = metadata.find(i => i.Name === 'Amount').Value;
        const receipt = metadata.find(i => i.Name === 'MpesaReceiptNumber').Value;
        const phone = metadata.find(i => i.Name === 'PhoneNumber').Value;
        
        console.log(`✅ Payment successful: KES ${amount}, Receipt: ${receipt}, Phone: ${phone}`);
        
        // Find transaction
        const transaction = await pool.query(
          'SELECT * FROM mpesa_transactions WHERE checkout_request_id = $1',
          [CheckoutRequestID]
        );
        
        if (transaction.rows.length > 0) {
          const tx = transaction.rows[0];
          
          await pool.query('BEGIN');
          
          // Update transaction
          await pool.query(
            `UPDATE mpesa_transactions 
             SET status = 'completed', 
                 mpesa_receipt_number = $1,
                 completed_at = NOW()
             WHERE checkout_request_id = $2`,
            [receipt, CheckoutRequestID]
          );
          
          // Get current balance
          const walletResult = await pool.query(
            'SELECT main_balance FROM wallets WHERE user_id = $1',
            [tx.user_id]
          );
          
          const currentBalance = parseFloat(walletResult.rows[0]?.main_balance || 0);
          
          // Update wallet
          await pool.query(
            `UPDATE wallets 
             SET main_balance = main_balance + $1,
                 lifetime_deposits = lifetime_deposits + $1,
                 last_updated = NOW()
             WHERE user_id = $2`,
            [tx.amount, tx.user_id]
          );
          
          // Create transaction record
          await pool.query(
            `INSERT INTO transactions 
             (user_id, type, amount, status, description, reference, method, payment_type, balance_before, balance_after)
             VALUES ($1, 'deposit', $2, 'completed', 'M-PESA deposit', $3, 'mpesa', 'stk', $4, $4 + $2)`,
            [tx.user_id, tx.amount, tx.reference, currentBalance]
          );
          
          await pool.query('COMMIT');
          console.log(`✅ Wallet updated for user ${tx.user_id}`);
        }
      } else {
        console.log(`❌ Payment failed: ${ResultDesc}`);
        
        await pool.query(
          `UPDATE mpesa_transactions 
           SET status = 'failed', 
               result_description = $1
           WHERE checkout_request_id = $2`,
          [ResultDesc, CheckoutRequestID]
        );
      }
    }
  } catch (error) {
    console.error('❌ Callback processing error:', error);
  }
});

// ==================== WITHDRAWAL ENDPOINT ====================
app.post('/api/withdraw', authenticateToken, async (req, res) => {
  const { userId, phoneNumber, amount, method } = req.body;
  
  try {
    console.log('📤 Withdrawal initiated:', { userId, phoneNumber, amount, method });
    
    await pool.query('BEGIN');
    
    // Check balance
    const walletResult = await pool.query(
      'SELECT main_balance FROM wallets WHERE user_id = $1',
      [userId]
    );
    
    if (walletResult.rows.length === 0) {
      await pool.query('ROLLBACK');
      return res.status(404).json({ error: 'Wallet not found' });
    }
    
    const currentBalance = parseFloat(walletResult.rows[0].main_balance);
    
    if (currentBalance < amount) {
      await pool.query('ROLLBACK');
      return res.status(400).json({ 
        error: 'Insufficient balance',
        available: currentBalance,
        requested: amount
      });
    }
    
    // Validate minimum withdrawal
    if (amount < 50) {
      await pool.query('ROLLBACK');
      return res.status(400).json({ error: 'Minimum withdrawal is KES 50' });
    }
    
    // Format phone number
    const formattedPhone = formatPhoneForMPesa(phoneNumber);
    
    // Generate reference
    const reference = 'WDR' + Date.now().toString().slice(-8);
    
    // Create withdrawal record
    const withdrawalResult = await pool.query(
      `INSERT INTO mpesa_transactions (user_id, phone_number, amount, reference, type, payment_type, status)
       VALUES ($1, $2, $3, $4, 'withdrawal', 'stk', 'pending')
       RETURNING id`,
      [userId, formattedPhone, amount, reference]
    );
    
    // Deduct from wallet
    await pool.query(
      `UPDATE wallets 
       SET main_balance = main_balance - $1,
           lifetime_withdrawals = lifetime_withdrawals + $1,
           last_updated = NOW()
       WHERE user_id = $2`,
      [amount, userId]
    );
    
    // Create transaction record
    await pool.query(
      `INSERT INTO transactions (user_id, type, amount, status, description, reference, method, balance_before, balance_after)
       VALUES ($1, 'withdrawal', $2, 'pending', 'Withdrawal via ' || $3, $4, $3, $5, $5 - $2)`,
      [userId, amount, method, reference, currentBalance]
    );
    
    await pool.query('COMMIT');
    
    // Simulate processing
    setTimeout(async () => {
      try {
        await pool.query(
          `UPDATE mpesa_transactions 
           SET status = 'completed', 
               mpesa_receipt_number = $1,
               completed_at = NOW()
           WHERE id = $2`,
          ['WDR' + Date.now().toString().slice(-10), withdrawalResult.rows[0].id]
        );
        
        await pool.query(
          `UPDATE transactions 
           SET status = 'completed', completed_at = NOW()
           WHERE reference = $1`,
          [reference]
        );
        
        console.log(`✅ Withdrawal completed for user ${userId}: KES ${amount}`);
      } catch (error) {
        console.error('Withdrawal completion error:', error);
      }
    }, 3000);
    
    res.json({ 
      success: true, 
      message: 'Withdrawal initiated successfully',
      transactionId: withdrawalResult.rows[0].id,
      reference
    });
    
  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('Withdrawal error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== FIXED BETTING ENDPOINTS ====================

// Place a bet - FIXED VERSION
app.post('/api/bets', authenticateToken, async (req, res) => {
  const { userId, selections, stake, totalOdds, potentialWinnings } = req.body;
  
  try {
    console.log('🎲 Bet placement:', { userId, stake, selections: selections.length });
    
    await pool.query('BEGIN');
    
    // Check wallet balance
    const walletResult = await pool.query(
      'SELECT main_balance FROM wallets WHERE user_id = $1',
      [userId]
    );
    
    if (walletResult.rows.length === 0) {
      await pool.query('ROLLBACK');
      return res.status(404).json({ error: 'Wallet not found' });
    }
    
    const currentBalance = parseFloat(walletResult.rows[0].main_balance);
    
    if (currentBalance < stake) {
      await pool.query('ROLLBACK');
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    // Generate a unique reference number
    const referenceNumber = 'BET-' + Date.now() + '-' + Math.random().toString(36).substring(2, 8).toUpperCase();
    
    // Create bet - FIXED with explicit column list
    const betResult = await pool.query(
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
    
    // Deduct from wallet
    await pool.query(
      `UPDATE wallets 
       SET main_balance = main_balance - $1,
           lifetime_bets = lifetime_bets + $1,
           last_updated = NOW()
       WHERE user_id = $2`,
      [stake, userId]
    );
    
    // Create transaction record
    await pool.query(
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
    
    await pool.query('COMMIT');
    
    res.json({ 
      success: true, 
      betId: betResult.rows[0].id,
      message: 'Bet placed successfully'
    });
    
  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('❌ Bet error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get user's bets - FIXED VERSION
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
  
  try {
    await pool.query('BEGIN');
    
    // Check if bet is pending
    const betResult = await pool.query(
      'SELECT * FROM bets WHERE id = $1 AND user_id = $2 AND status = $3',
      [betId, userId, 'pending']
    );
    
    if (betResult.rows.length === 0) {
      await pool.query('ROLLBACK');
      return res.status(400).json({ error: 'Bet not found or cannot be cancelled' });
    }
    
    const bet = betResult.rows[0];
    
    // Update bet status
    await pool.query(
      'UPDATE bets SET status = $1, updated_at = NOW() WHERE id = $2',
      ['cancelled', betId]
    );
    
    // Refund stake to wallet
    await pool.query(
      `UPDATE wallets 
       SET main_balance = main_balance + $1,
           last_updated = NOW()
       WHERE user_id = $2`,
      [bet.stake, userId]
    );
    
    // Create refund transaction
    await pool.query(
      `INSERT INTO transactions (user_id, type, amount, status, description, reference)
       VALUES ($1, 'adjustment', $2, 'completed', 'Bet cancellation refund', $3)`,
      [userId, bet.stake, 'REF-' + Date.now()]
    );
    
    await pool.query('COMMIT');
    
    res.json({ success: true, message: 'Bet cancelled and stake refunded' });
    
  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('❌ Cancel bet error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== FIXED BONUS ENDPOINTS ====================

// Get user bonuses - FIXED with correct column names
app.get('/api/bonuses/:userId', authenticateToken, async (req, res) => {
  try {
    const userId = req.params.userId;
    
    // Get claimed bonuses for user - use claimed_at instead of created_at
    const claimedResult = await pool.query(
      `SELECT ub.*, b.name, b.description, b.type, b.amount as bonus_amount,
              b.percentage, b.min_deposit, b.max_amount
       FROM user_bonuses ub
       JOIN bonuses b ON ub.bonus_id = b.id
       WHERE ub.user_id = $1
       ORDER BY ub.claimed_at DESC`,
      [userId]
    );
    
    // Get available bonuses (not yet claimed by user)
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

// Claim welcome bonus - FIXED
app.post('/api/bonuses/welcome/claim', authenticateToken, async (req, res) => {
  const { userId } = req.body;
  
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
    
    // Get welcome bonus
    const bonusResult = await pool.query(
      "SELECT * FROM bonuses WHERE type = 'welcome' LIMIT 1"
    );
    
    if (bonusResult.rows.length === 0) {
      return res.status(404).json({ error: 'Welcome bonus not found' });
    }
    
    const bonus = bonusResult.rows[0];
    
    await pool.query('BEGIN');
    
    // Get current balance
    const walletResult = await pool.query(
      'SELECT main_balance FROM wallets WHERE user_id = $1',
      [userId]
    );
    
    const currentBalance = parseFloat(walletResult.rows[0]?.main_balance || 0);
    
    // Create user bonus - using claimed_at which exists
    await pool.query(
      `INSERT INTO user_bonuses (user_id, bonus_id, amount, status, claimed_at)
       VALUES ($1, $2, $3, 'completed', NOW())`,
      [userId, bonus.id, bonus.amount]
    );
    
    // Update wallet
    await pool.query(
      `UPDATE wallets 
       SET main_balance = main_balance + $1,
           last_updated = NOW()
       WHERE user_id = $2`,
      [bonus.amount, userId]
    );
    
    // Create transaction
    await pool.query(
      `INSERT INTO transactions (user_id, type, amount, status, description, reference, balance_before, balance_after)
       VALUES ($1, 'bonus', $2, 'completed', 'Welcome bonus claimed', $3, $4, $4 + $2)`,
      [userId, bonus.amount, 'BONUS-' + Date.now(), currentBalance]
    );
    
    await pool.query('COMMIT');
    
    res.json({ 
      success: true, 
      message: 'Welcome bonus claimed successfully',
      amount: bonus.amount
    });
    
  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('❌ Claim bonus error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== JACKPOT ENDPOINTS ====================

// Get current jackpot week
app.get('/api/jackpot/current', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM jackpot_weeks 
       WHERE status = 'open' 
       ORDER BY created_at DESC 
       LIMIT 1`
    );
    
    if (result.rows.length === 0) {
      return res.json({ message: 'No active jackpot' });
    }
    
    res.json(result.rows[0]);
    
  } catch (error) {
    console.error('❌ Jackpot error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get jackpot matches
app.get('/api/jackpot/matches/:weekId', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT matches FROM jackpot_weeks WHERE id = $1',
      [req.params.weekId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Jackpot week not found' });
    }
    
    res.json(result.rows[0].matches);
    
  } catch (error) {
    console.error('❌ Jackpot matches error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Submit jackpot entry
app.post('/api/jackpot/entry', authenticateToken, async (req, res) => {
  const { userId, weekId, weekNumber, selections, stake, totalOdds, potentialWinnings } = req.body;
  
  try {
    await pool.query('BEGIN');
    
    // Check wallet balance
    const walletResult = await pool.query(
      'SELECT main_balance FROM wallets WHERE user_id = $1',
      [userId]
    );
    
    const currentBalance = parseFloat(walletResult.rows[0].main_balance);
    
    if (currentBalance < stake) {
      await pool.query('ROLLBACK');
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    // Create jackpot entry
    const entryResult = await pool.query(
      `INSERT INTO jackpot_entries (
        user_id, week_id, week_number, selections, stake, total_odds, potential_winnings, status
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
      [userId, weekId, weekNumber, JSON.stringify(selections), stake, totalOdds, potentialWinnings, 'pending']
    );
    
    // Update total pool
    await pool.query(
      `UPDATE jackpot_weeks 
       SET total_pool = total_pool + $1, total_entries = total_entries + 1 
       WHERE id = $2`,
      [stake, weekId]
    );
    
    // Deduct from wallet
    await pool.query(
      `UPDATE wallets 
       SET main_balance = main_balance - $1,
           lifetime_bets = lifetime_bets + $1,
           last_updated = NOW()
       WHERE user_id = $2`,
      [stake, userId]
    );
    
    // Create transaction
    await pool.query(
      `INSERT INTO transactions (
        user_id, type, amount, status, description, reference, balance_before, balance_after
      ) VALUES ($1, 'jackpot', $2, 'completed', 'Jackpot entry', $3, $4, $4 - $2)`,
      [userId, stake, 'JP-' + Date.now(), currentBalance]
    );
    
    await pool.query('COMMIT');
    
    res.json({ 
      success: true, 
      entryId: entryResult.rows[0].id,
      message: 'Jackpot entry submitted successfully'
    });
    
  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('❌ Jackpot entry error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get jackpot leaderboard
app.get('/api/jackpot/leaderboard/:weekId', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT je.*, p.full_name 
       FROM jackpot_entries je
       JOIN profiles p ON je.user_id = p.id
       WHERE je.week_id = $1 AND je.status = 'pending'
       ORDER BY je.created_at`,
      [req.params.weekId]
    );
    
    res.json(result.rows);
    
  } catch (error) {
    console.error('❌ Leaderboard error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== SUPPORT TICKETS ====================

// Create support ticket
app.post('/api/support/tickets', authenticateToken, async (req, res) => {
  const { userId, subject, message, category } = req.body;
  
  try {
    const result = await pool.query(
      `INSERT INTO support_tickets (
        user_id, subject, message, category, ticket_number, status
      ) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, ticket_number`,
      [userId, subject, message, category, 'TKT-' + Date.now(), 'open']
    );
    
    res.json({ 
      success: true, 
      ticketId: result.rows[0].id,
      ticketNumber: result.rows[0].ticket_number
    });
    
  } catch (error) {
    console.error('❌ Ticket creation error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get user's tickets
app.get('/api/support/tickets/:userId', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM support_tickets 
       WHERE user_id = $1 
       ORDER BY created_at DESC`,
      [req.params.userId]
    );
    
    res.json(result.rows);
    
  } catch (error) {
    console.error('❌ Tickets error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Add reply to ticket
app.post('/api/support/tickets/:ticketId/reply', authenticateToken, async (req, res) => {
  const { ticketId } = req.params;
  const { userId, message } = req.body;
  
  try {
    await pool.query('BEGIN');
    
    // Add reply
    await pool.query(
      `INSERT INTO ticket_replies (ticket_id, user_id, message)
       VALUES ($1, $2, $3)`,
      [ticketId, userId, message]
    );
    
    // Update ticket status
    await pool.query(
      `UPDATE support_tickets 
       SET status = 'in_progress', updated_at = NOW()
       WHERE id = $1`,
      [ticketId]
    );
    
    await pool.query('COMMIT');
    
    res.json({ success: true });
    
  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('❌ Reply error:', error);
    res.status(500).json({ error: error.message });
  }
});
// ==================== FAQ ENDPOINT ====================

// Get FAQs
app.get('/api/support/faqs', async (req, res) => {
  try {
    // You can store FAQs in a database table or return static ones
    // For now, return a comprehensive list of FAQs
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
    
    // Store feedback in database if needed
    // await pool.query(
    //   'INSERT INTO feedback (user_id, rating, comment, category) VALUES ($1, $2, $3, $4)',
    //   [userId, rating, comment, category]
    // );
    
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
    // You can implement real stats from database
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
// ==================== WITHDRAWAL ENDPOINT ====================
app.post('/api/withdraw', authenticateToken, async (req, res) => {
  const { userId, phoneNumber, amount, method } = req.body;
  
  try {
    console.log('📤 Withdrawal initiated:', { userId, phoneNumber, amount, method });
    
    await pool.query('BEGIN');
    
    // Check if user has enough balance
    const walletResult = await pool.query(
      'SELECT main_balance FROM wallets WHERE user_id = $1',
      [userId]
    );
    
    if (walletResult.rows.length === 0) {
      await pool.query('ROLLBACK');
      return res.status(404).json({ error: 'Wallet not found' });
    }
    
    const currentBalance = parseFloat(walletResult.rows[0].main_balance);
    
    if (currentBalance < amount) {
      await pool.query('ROLLBACK');
      return res.status(400).json({ 
        error: 'Insufficient balance',
        available: currentBalance,
        requested: amount
      });
    }
    
    // Validate minimum withdrawal
    if (amount < 50) {
      await pool.query('ROLLBACK');
      return res.status(400).json({ error: 'Minimum withdrawal is KES 50' });
    }
    
    // Format phone number
    const formattedPhone = formatPhoneForMPesa(phoneNumber);
    
    // Generate reference
    const reference = 'WDR' + Date.now().toString().slice(-8);
    
    // Create withdrawal transaction record
    const withdrawalResult = await pool.query(
      `INSERT INTO mpesa_transactions (user_id, phone_number, amount, reference, type, payment_type, status)
       VALUES ($1, $2, $3, $4, 'withdrawal', 'stk', 'pending')
       RETURNING id`,
      [userId, formattedPhone, amount, reference]
    );
    
    // Deduct from wallet
    await pool.query(
      `UPDATE wallets 
       SET main_balance = main_balance - $1,
           lifetime_withdrawals = lifetime_withdrawals + $1,
           last_updated = NOW()
       WHERE user_id = $2`,
      [amount, userId]
    );
    
    // Create transaction record
    await pool.query(
      `INSERT INTO transactions (user_id, type, amount, status, description, reference, method, balance_before, balance_after)
       VALUES ($1, 'withdrawal', $2, 'pending', 'Withdrawal via ' || $3, $4, $3, $5, $5 - $2)`,
      [userId, amount, method, reference, currentBalance]
    );
    
    await pool.query('COMMIT');
    
    // Simulate processing
    setTimeout(async () => {
      try {
        await pool.query(
          `UPDATE mpesa_transactions 
           SET status = 'completed', 
               mpesa_receipt_number = $1,
               completed_at = NOW()
           WHERE id = $2`,
          ['WDR' + Date.now().toString().slice(-10), withdrawalResult.rows[0].id]
        );
        
        await pool.query(
          `UPDATE transactions 
           SET status = 'completed', completed_at = NOW()
           WHERE reference = $1`,
          [reference]
        );
        
        console.log(`✅ Withdrawal completed for user ${userId}: KES ${amount}`);
      } catch (error) {
        console.error('Withdrawal completion error:', error);
      }
    }, 3000);
    
    res.json({ 
      success: true, 
      message: 'Withdrawal initiated successfully',
      transactionId: withdrawalResult.rows[0].id,
      reference
    });
    
  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('❌ Withdrawal error:', error);
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
  console.log(`   🎲 POST /api/bets (FIXED)`);
  console.log(`   📋 GET  /api/bets/:userId (FIXED)`);
  console.log(`   ❌ POST /api/bets/:betId/cancel`);
  console.log(`   🎁 GET  /api/bonuses/:userId (FIXED)`);
  console.log(`   🎁 POST /api/bonuses/welcome/claim (NEW)`);
  console.log(`   🏆 GET  /api/jackpot/current`);
  console.log(`   🏆 POST /api/jackpot/entry`);
  console.log(`   📞 POST /api/mpesa/stkpush`);
  console.log(`   🔍 GET  /api/payment/status/:transactionId`);
  console.log(`   📞 POST /api/mpesa/callback`);
  console.log(`   🎫 POST /api/support/tickets`);
  console.log(`   ⚽ GET  /api/leagues`);
  console.log(`   ⚽ GET  /api/matches/upcoming`);
  console.log(`   🔴 GET  /api/matches/live`);
  console.log(`   📊 GET  /api/stats/:userId`);
  console.log(`   📚 GET  /api/support/faqs (NEW)`);
console.log(`   📞 GET  /api/support/contact (NEW)`);
console.log(`   📝 POST /api/support/feedback (NEW)`);
console.log(`   📊 GET  /api/support/stats (NEW)`);
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
