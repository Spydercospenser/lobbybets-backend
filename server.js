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

// ==================== ADMIN AUTHENTICATION MIDDLEWARE ====================
// Define this ONLY ONCE at the top of your admin section
const authenticateAdmin = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const result = await pool.query(
      'SELECT id, full_name, email, phone, role, is_active FROM admins WHERE id = $1',
      [decoded.adminId]
    );
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    
    const admin = result.rows[0];
    
    if (!admin.is_active) {
      return res.status(403).json({ error: 'Account is deactivated' });
    }
    
    req.admin = admin;
    next();
  } catch (error) {
    console.error('❌ Admin auth error:', error);
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

// Admin login (public)
app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    console.log('👑 Admin login attempt for:', email);
    
    const result = await pool.query(
      'SELECT id, full_name, email, phone, role, password_hash, is_active FROM admins WHERE email = $1',
      [email]
    );
    
    if (result.rows.length === 0) {
      console.log('❌ Admin not found:', email);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const admin = result.rows[0];
    
    // Check if account is active
    if (!admin.is_active) {
      console.log('❌ Admin account deactivated:', email);
      return res.status(403).json({ error: 'Account is deactivated. Contact super admin.' });
    }
    
    // Verify password
    const validPassword = await bcrypt.compare(password, admin.password_hash);
    if (!validPassword) {
      console.log('❌ Invalid password for admin:', email);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Update last login
    await pool.query(
      'UPDATE admins SET last_login_at = NOW(), last_login_ip = $1 WHERE id = $2',
      [req.ip || req.connection.remoteAddress, admin.id]
    );
    
    // Generate JWT
    const token = jwt.sign(
      { adminId: admin.id, email: admin.email, role: admin.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    console.log('✅ Admin login successful:', admin.email, 'Role:', admin.role);
    
    res.json({
      success: true,
      token,
      admin: {
        id: admin.id,
        full_name: admin.full_name,
        email: admin.email,
        phone: admin.phone,
        role: admin.role
      }
    });
    
  } catch (error) {
    console.error('❌ Admin login error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Forgot password - simple reset without OTP (public)
app.post('/api/admin/forgot-password', async (req, res) => {
  const { email, newPassword } = req.body;
  
  try {
    console.log('🔑 Password reset requested for:', email);
    
    // Validate input
    if (!email || !newPassword) {
      return res.status(400).json({ error: 'Email and new password are required' });
    }
    
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    // Check if admin exists
    const admin = await pool.query(
      'SELECT id FROM admins WHERE email = $1',
      [email]
    );
    
    if (admin.rows.length === 0) {
      console.log('❌ Admin not found for password reset:', email);
      return res.status(404).json({ error: 'Admin not found' });
    }
    
    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    // Update password
    await pool.query(
      'UPDATE admins SET password_hash = $1, updated_at = NOW() WHERE id = $2',
      [hashedPassword, admin.rows[0].id]
    );
    
    console.log('✅ Password reset successful for:', email);
    
    res.json({
      success: true,
      message: 'Password reset successfully. You can now login with your new password.'
    });
    
  } catch (error) {
    console.error('❌ Password reset error:', error);
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
app.get('/api/admin/profile', authenticateAdmin, async (req, res) => {
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
    
    // Generate JWT with UUID
    const expiresIn = process.env.JWT_EXPIRES_IN || '7d';
    console.log('🔑 Using expiration for registration:', expiresIn);
    console.log('🔑 User ID from database (UUID):', userId);
    
    const token = jwt.sign(
      { 
        userId: userId,  // This is the UUID from database
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
    
    // Generate JWT with UUID
    const expiresIn = process.env.JWT_EXPIRES_IN || '7d';
    console.log('🔑 JWT_EXPIRES_IN from env:', expiresIn);
    console.log('🔑 User ID from database (UUID):', user.id);
    
    const token = jwt.sign(
      { 
        userId: user.id,  // This is the UUID from database
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

// ==================== M-PESA CONFIGURATION ====================
const MPESA_CONFIG = {
  // Production endpoints
  stkPushUrl: 'https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
  queryUrl: 'https://api.safaricom.co.ke/mpesa/stkpushquery/v1/query',
  tokenUrl: 'https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials',
  
  // Your production credentials
  consumerKey: 'EiTjMcrIYbxBJY1G7UiNVu62YwxVEfEQ1qdTA9u7uY9nhOBP',
  consumerSecret: 'GaPQ3RxOpJnd03Sx96PMX1igq9nDSBChFjGky0f1QNZOx9jALtPt07v9GmpHCMoc',
  businessShortCode: '4011243',
  passkey: 'ed0f022db9398b8082f6c4114a8bcb2d25a9685c2383790947a5aa76cd5c30e5',
  
  // IMPORTANT: This MUST be a publicly accessible URL!
  // Use ngrok for development: ngrok http 3000
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
      timeout: 10000 // 10 second timeout
    });

    mpesaAccessToken = response.data.access_token;
    // Token expires in 1 hour, set expiry to 55 minutes
    tokenExpiryTime = new Date(Date.now() + 55 * 60 * 1000);
    
    console.log('✅ M-PESA token generated successfully');
    return mpesaAccessToken;
  } catch (error) {
    console.error('❌ Failed to get M-PESA token:', error.response?.data || error.message);
    throw new Error('Failed to get M-PESA access token');
  }
};

// ==================== FIXED M-PESA STK PUSH WITH USER VALIDATION ====================
app.post('/api/mpesa/stkpush', authenticateToken, async (req, res) => {
  const { userId, phoneNumber, amount } = req.body;
  
  try {
    console.log('📱 ===== M-PESA STK PUSH INITIATED =====');
    console.log('📱 User ID from request:', userId);
    console.log('📱 User ID type:', typeof userId);
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

    // ===== CRITICAL: Find user by phone number since token might have numeric ID =====
    console.log('🔍 Looking up user by phone number:', formattedPhone);
    
    // Try to find user by the formatted phone number
    const userByPhone = await pool.query(
      'SELECT id, phone, full_name FROM profiles WHERE phone = $1',
      [formattedPhone]
    );
    
    let dbUserId;
    
    if (userByPhone.rows.length > 0) {
      dbUserId = userByPhone.rows[0].id;
      console.log('✅ Found user by phone:');
      console.log('   - UUID:', dbUserId);
      console.log('   - Phone:', userByPhone.rows[0].phone);
      console.log('   - Name:', userByPhone.rows[0].full_name);
    } else {
      console.log('❌ User not found with phone:', formattedPhone);
      
      // Try with the original phone number
      const originalPhoneSearch = await pool.query(
        'SELECT id, phone, full_name FROM profiles WHERE phone = $1',
        [phoneNumber]
      );
      
      if (originalPhoneSearch.rows.length > 0) {
        dbUserId = originalPhoneSearch.rows[0].id;
        console.log('✅ Found user by original phone:');
        console.log('   - UUID:', dbUserId);
        console.log('   - Phone:', originalPhoneSearch.rows[0].phone);
      } else {
        console.error('❌ User NOT FOUND with any phone format');
        
        // Debug: List some users to see what phones exist
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

    // Get M-PESA token
    console.log('🔄 Getting M-PESA token...');
    const token = await getMpesaToken();
    console.log('✅ Token obtained');

    // Generate timestamp
    const date = new Date();
    const timestamp = date.getFullYear() +
      String(date.getMonth() + 1).padStart(2, '0') +
      String(date.getDate()).padStart(2, '0') +
      String(date.getHours()).padStart(2, '0') +
      String(date.getMinutes()).padStart(2, '0') +
      String(date.getSeconds()).padStart(2, '0');
    
    // Generate password
    const password = Buffer.from(
      `${MPESA_CONFIG.businessShortCode}${MPESA_CONFIG.passkey}${timestamp}`
    ).toString('base64');

    // Generate unique reference
    const reference = 'LBB' + Date.now() + Math.random().toString(36).substring(2, 10).toUpperCase();

    // Prepare STK Push request
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

    // Send to Safaricom
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

    // Insert transaction with the database UUID
  // Insert transaction with the database UUID - USING EXACT COLUMN NAMES
const result = await pool.query(
  `INSERT INTO mpesa_transactions (
    user_id,
    phone_number,
    amount,
    reference,
    checkout_request_id,
    merchant_request_id,  -- Make sure this matches exactly
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
    dbUserId,                          // $1 - UUID from database
    formattedPhone,                    // $2
    amount,                            // $3
    reference,                         // $4
    CheckoutRequestID || null,         // $5
    MerchantRequestID || null,          // $6
    'deposit',                          // $7
    'stk',                              // $8
    'pending',                          // $9
    ResponseCode ? parseInt(ResponseCode) : null,  // $10
    ResponseDescription || null,         // $11
    CustomerMessage || null              // $12
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
    
    if (error.code === '23503') { // Foreign key violation
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

// ==================== FIXED M-PESA CALLBACK ====================
app.post('/api/mpesa/callback', async (req, res) => {
  console.log('📞 ===== M-PESA CALLBACK RECEIVED =====');
  console.log('📞 Callback body:', JSON.stringify(req.body, null, 2));
  
  // Always acknowledge immediately
  res.json({ ResultCode: 0, ResultDesc: 'Success' });
  
  try {
    const { Body } = req.body;
    
    if (!Body?.stkCallback) {
      console.log('❌ Invalid callback data');
      return;
    }

    const { 
      ResultCode, 
      ResultDesc, 
      CheckoutRequestID, 
      CallbackMetadata 
    } = Body.stkCallback;

    console.log(`📞 CheckoutRequestID: ${CheckoutRequestID}, ResultCode: ${ResultCode}`);

    // Find transaction
    const transaction = await pool.query(
      'SELECT * FROM mpesa_transactions WHERE checkout_request_id = $1',
      [CheckoutRequestID]
    );
    
    if (transaction.rows.length === 0) {
      console.log('❌ Transaction not found:', CheckoutRequestID);
      return;
    }

    const tx = transaction.rows[0];
    console.log('📞 Found transaction:', tx.id);

    if (ResultCode === 0) {
      // Payment successful - extract metadata
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

      await pool.query('BEGIN');

      // Update transaction - include all fields
      await pool.query(
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
             updated_at = NOW()
         WHERE user_id = $2`,
        [amount, tx.user_id]
      );

      // Create transaction record
      await pool.query(
        `INSERT INTO transactions 
         (user_id, type, amount, status, description, reference, balance_before, balance_after, created_at)
         VALUES ($1, 'deposit', $2, 'completed', 'M-PESA deposit', $3, $4, $4 + $2, NOW())`,
        [tx.user_id, amount, tx.reference, currentBalance]
      );

      await pool.query('COMMIT');
      console.log(`✅ Wallet updated for user ${tx.user_id}: +KES ${amount} (Receipt: ${receipt})`);
      
    } else {
      // Payment failed
      console.log(`❌ Payment failed: ${ResultDesc}`);
      
      await pool.query(
        `UPDATE mpesa_transactions 
         SET status = 'failed',
             result_code = $1,
             result_description = $2,
             updated_at = NOW()
         WHERE id = $3`,
        [ResultCode, ResultDesc, tx.id]
      );
    }
    
  } catch (error) {
    console.error('❌ Callback error:', error);
    await pool.query('ROLLBACK').catch(e => {});
  }
});

// ==================== QUERY STK PUSH STATUS ====================
app.post('/api/mpesa/query', authenticateToken, async (req, res) => {
  const { checkoutRequestId } = req.body;
  
  try {
    const token = await getMpesaToken();
    
    // Generate timestamp
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

// Reset password endpoint (no OTP, direct reset)
app.post('/api/reset-password', async (req, res) => {
  const { phone, newPassword } = req.body;
  
  try {
    console.log('🔐 Password reset attempt for phone:', phone);
    
    // Validate input
    if (!phone || !newPassword) {
      return res.status(400).json({ error: 'Phone and new password are required' });
    }
    
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    // Format phone number (handle both 07... and 254... formats)
    let formattedPhone = normalizePhoneForDatabase(phone);
    console.log('📱 Formatted phone for lookup:', formattedPhone);
    
    // Check if user exists
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
    
    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    // Update password in database
    await pool.query(
      `UPDATE profiles 
       SET password_hash = $1, 
           updated_at = NOW(),
           last_password_reset = NOW()
       WHERE id = $2`,
      [hashedPassword, user.id]
    );
    
    // Log password reset in audit table (optional)
    await pool.query(
      `INSERT INTO password_resets (user_id, reset_method, reset_at)
       VALUES ($1, 'direct', NOW())`,
      [user.id]
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
// ==================== PAYBILL PAYMENT ENDPOINTS ====================

// Initiate Paybill payment
app.post('/api/payments/paybill/initiate', authenticateToken, async (req, res) => {
  const { userId, phoneNumber, amount } = req.body;
  
  try {
    console.log('💰 Paybill initiation for user:', userId);
    
    // Verify user matches token
    if (req.user.userId !== userId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    // Check if user has a pending Paybill payment
    const pendingPayment = await pool.query(
      `SELECT id FROM paybill_payments 
       WHERE user_id = $1 AND status = 'pending' AND expires_at > NOW()`,
      [userId]
    );
    
    if (pendingPayment.rows.length > 0) {
      return res.json({
        success: true,
        message: 'You have a pending Paybill payment',
        paymentId: pendingPayment.rows[0].id,
        pending: true
      });
    }
    
    // Generate unique account number
    const accountNumber = `LB${Date.now().toString().slice(-8)}${Math.floor(Math.random() * 100)}`;
    
    // Create pending payment record
    const result = await pool.query(
      `INSERT INTO paybill_payments 
       (user_id, amount, phone_number, account_number, business_number, status)
       VALUES ($1, $2, $3, $4, $5, 'pending')
       RETURNING id, account_number, business_number, expires_at`,
      [userId, amount, phoneNumber, accountNumber, '4011243']
    );
    
    const payment = result.rows[0];
    
    // Create a pending transaction record
    const transaction = await pool.query(
      `INSERT INTO transactions 
       (user_id, type, amount, status, description, method, reference, metadata)
       VALUES ($1, 'deposit', $2, 'pending', 'Paybill deposit', 'paybill', $3, $4)
       RETURNING id`,
      [userId, amount, `PB-${Date.now()}`, JSON.stringify({ paymentId: payment.id })]
    );
    
    // Update payment with transaction ID
    await pool.query(
      'UPDATE paybill_payments SET transaction_id = $1 WHERE id = $2',
      [transaction.rows[0].id, payment.id]
    );
    
    res.json({
      success: true,
      paymentId: payment.id,
      transactionId: transaction.rows[0].id,
      accountNumber: payment.account_number,
      businessNumber: payment.business_number,
      amount,
      expiresAt: payment.expires_at,
      instructions: {
        business: '4011243',
        account: payment.account_number,
        amount: amount
      }
    });
    
  } catch (error) {
    console.error('❌ Paybill initiation error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Confirm Paybill payment (user clicks "I have paid")
app.post('/api/payments/paybill/confirm', authenticateToken, async (req, res) => {
  const { paymentId, confirmationCode } = req.body;
  
  try {
    console.log('💰 Confirming Paybill payment:', paymentId);
    
    // Get payment details
    const payment = await pool.query(
      `SELECT pp.*, u.full_name 
       FROM paybill_payments pp
       JOIN profiles u ON pp.user_id = u.id
       WHERE pp.id = $1`,
      [paymentId]
    );
    
    if (payment.rows.length === 0) {
      return res.status(404).json({ error: 'Payment not found' });
    }
    
    const payData = payment.rows[0];
    
    // Verify user owns this payment
    if (payData.user_id !== req.user.userId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    // Check if payment is already confirmed
    if (payData.status === 'confirmed') {
      return res.json({
        success: true,
        message: 'Payment already confirmed',
        alreadyConfirmed: true
      });
    }
    
    // Check if payment has expired
    if (new Date(payData.expires_at) < new Date()) {
      await pool.query(
        'UPDATE paybill_payments SET status = $1 WHERE id = $2',
        ['expired', paymentId]
      );
      return res.status(400).json({ error: 'Payment has expired. Please start a new deposit.' });
    }
    
    // In a real system, you would verify with M-PESA API here
    // For now, we'll simulate a successful confirmation
    
    // Update payment status
    await pool.query(
      `UPDATE paybill_payments 
       SET status = 'confirmed', 
           confirmed_at = NOW(),
           confirmation_code = $1
       WHERE id = $2`,
      [confirmationCode || `CONF-${Date.now()}`, paymentId]
    );
    
    // Update transaction status to completed
    await pool.query(
      `UPDATE transactions 
       SET status = 'completed', 
           completed_at = NOW(),
           description = 'Paybill deposit confirmed'
       WHERE id = $1`,
      [payData.transaction_id]
    );
    
    // Update wallet balance
    await pool.query(
      `UPDATE wallets 
       SET main_balance = main_balance + $1,
           lifetime_deposits = lifetime_deposits + $1,
           last_updated = NOW()
       WHERE user_id = $2`,
      [payData.amount, payData.user_id]
    );
    
    // Create notification (optional)
    console.log(`✅ Payment confirmed for user ${payData.user_id}: +KES ${payData.amount}`);
    
    res.json({
      success: true,
      message: 'Payment confirmed successfully',
      amount: payData.amount
    });
    
  } catch (error) {
    console.error('❌ Paybill confirmation error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Check Paybill payment status
app.get('/api/payments/paybill/status/:paymentId', authenticateToken, async (req, res) => {
  const { paymentId } = req.params;
  
  try {
    const payment = await pool.query(
      `SELECT pp.*, t.status as transaction_status
       FROM paybill_payments pp
       LEFT JOIN transactions t ON pp.transaction_id = t.id
       WHERE pp.id = $1`,
      [paymentId]
    );
    
    if (payment.rows.length === 0) {
      return res.status(404).json({ error: 'Payment not found' });
    }
    
    const payData = payment.rows[0];
    
    // Verify user owns this payment
    if (payData.user_id !== req.user.userId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    res.json({
      status: payData.status,
      amount: payData.amount,
      expiresAt: payData.expires_at,
      transactionStatus: payData.transaction_status
    });
    
  } catch (error) {
    console.error('❌ Paybill status error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== GAME BETTING ENDPOINTS ====================

// Place a game bet (Aviator/JetX)
app.post('/api/games/bet', authenticateToken, async (req, res) => {
  const { userId, gameType, stake, autoCashout } = req.body;
  
  try {
    console.log('🎲 Placing game bet:', { userId, gameType, stake });
    
    // Verify user
    if (req.user.userId !== userId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    // Validate stake
    if (stake < 10 || stake > 5000) {
      return res.status(400).json({ error: 'Stake must be between KES 10 and 5,000' });
    }
    
    // Check user balance
    const wallet = await pool.query(
      'SELECT main_balance FROM wallets WHERE user_id = $1',
      [userId]
    );
    
    if (wallet.rows.length === 0) {
      return res.status(404).json({ error: 'Wallet not found' });
    }
    
    const currentBalance = parseFloat(wallet.rows[0].main_balance);
    
    if (currentBalance < stake) {
      return res.status(400).json({ 
        error: 'Insufficient balance',
        available: currentBalance,
        required: stake
      });
    }
    
    // Start transaction
    await pool.query('BEGIN');
    
    // Create bet record
    const betResult = await pool.query(
      `INSERT INTO bets (
        user_id, 
        selections, 
        stake, 
        total_odds, 
        potential_winnings,
        status, 
        bet_type, 
        game_type,
        reference_number,
        created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
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
        `${gameType}-${Date.now()}-${Math.floor(Math.random() * 1000)}`
      ]
    );
    
    const betId = betResult.rows[0].id;
    
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
        user_id, type, amount, status, description, 
        reference, balance_before, balance_after
      ) VALUES ($1, 'bet', $2, 'completed', $3, $4, $5, $6)`,
      [
        userId,
        stake,
        `${gameType} bet placed`,
        `BET-${betId}`,
        currentBalance,
        currentBalance - stake
      ]
    );
    
    await pool.query('COMMIT');
    
    console.log(`✅ Bet placed: User ${userId} bet KES ${stake} on ${gameType}`);
    
    res.json({
      success: true,
      betId,
      message: 'Bet placed successfully',
      newBalance: currentBalance - stake
    });
    
  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('❌ Game bet error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Cashout from game
app.post('/api/games/cashout', authenticateToken, async (req, res) => {
  const { betId, userId, multiplier } = req.body;
  
  try {
    console.log('💰 Processing cashout:', { betId, userId, multiplier });
    
    // Verify user
    if (req.user.userId !== userId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    // Get bet details
    const bet = await pool.query(
      'SELECT * FROM bets WHERE id = $1 AND user_id = $2 AND status = $3',
      [betId, userId, 'pending']
    );
    
    if (bet.rows.length === 0) {
      return res.status(404).json({ error: 'Bet not found or already settled' });
    }
    
    const betData = bet.rows[0];
    const winAmount = betData.stake * multiplier;
    
    // Start transaction
    await pool.query('BEGIN');
    
    // Update bet
    await pool.query(
      `UPDATE bets 
       SET status = 'cashed_out', 
           cashout_multiplier = $1,
           actual_winnings = $2,
           settled_at = NOW()
       WHERE id = $3`,
      [multiplier, winAmount, betId]
    );
    
    // Get current balance
    const wallet = await pool.query(
      'SELECT main_balance FROM wallets WHERE user_id = $1',
      [userId]
    );
    
    const currentBalance = parseFloat(wallet.rows[0].main_balance);
    
    // Add winnings to wallet
    await pool.query(
      `UPDATE wallets 
       SET main_balance = main_balance + $1,
           lifetime_winnings = lifetime_winnings + $1,
           last_updated = NOW()
       WHERE user_id = $2`,
      [winAmount, userId]
    );
    
    // Create win transaction
    await pool.query(
      `INSERT INTO transactions (
        user_id, type, amount, status, description, 
        reference, balance_before, balance_after
      ) VALUES ($1, 'win', $2, 'completed', $3, $4, $5, $6)`,
      [
        userId,
        winAmount,
        `Cashed out at ${multiplier}x`,
        `WIN-${betId}`,
        currentBalance,
        currentBalance + winAmount
      ]
    );
    
    await pool.query('COMMIT');
    
    console.log(`✅ Cashout processed: User ${userId} won KES ${winAmount} at ${multiplier}x`);
    
    res.json({
      success: true,
      winAmount,
      message: `Cashed out at ${multiplier}x! You won KES ${winAmount}`,
      newBalance: currentBalance + winAmount
    });
    
  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('❌ Cashout error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get game history
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

// ==================== PAYBILL PAYMENT ENDPOINTS ====================

// Initiate Paybill payment
app.post('/api/payments/paybill/initiate', authenticateToken, async (req, res) => {
  const { userId, phoneNumber, amount } = req.body;
  
  try {
    console.log('💰 Paybill initiation for user:', userId);
    
    // Verify user matches token
    if (req.user.userId !== userId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    // Check if user has a pending Paybill payment
    const pendingPayment = await pool.query(
      `SELECT id FROM paybill_payments 
       WHERE user_id = $1 AND status = 'pending' AND expires_at > NOW()`,
      [userId]
    );
    
    if (pendingPayment.rows.length > 0) {
      return res.json({
        success: true,
        message: 'You have a pending Paybill payment',
        paymentId: pendingPayment.rows[0].id,
        pending: true
      });
    }
    
    // Generate unique account number
    const accountNumber = `LB${Date.now().toString().slice(-8)}${Math.floor(Math.random() * 100)}`;
    
    // Create pending payment record
    const result = await pool.query(
      `INSERT INTO paybill_payments 
       (user_id, amount, phone_number, account_number, business_number, status)
       VALUES ($1, $2, $3, $4, $5, 'pending')
       RETURNING id, account_number, business_number, expires_at`,
      [userId, amount, phoneNumber, accountNumber, '4011243']
    );
    
    const payment = result.rows[0];
    
    // Create a pending transaction record
    const transaction = await pool.query(
      `INSERT INTO transactions 
       (user_id, type, amount, status, description, method, reference, metadata)
       VALUES ($1, 'deposit', $2, 'pending', 'Paybill deposit', 'paybill', $3, $4)
       RETURNING id`,
      [userId, amount, `PB-${Date.now()}`, JSON.stringify({ paymentId: payment.id })]
    );
    
    // Update payment with transaction ID
    await pool.query(
      'UPDATE paybill_payments SET transaction_id = $1 WHERE id = $2',
      [transaction.rows[0].id, payment.id]
    );
    
    res.json({
      success: true,
      paymentId: payment.id,
      transactionId: transaction.rows[0].id,
      accountNumber: payment.account_number,
      businessNumber: payment.business_number,
      amount,
      expiresAt: payment.expires_at,
      instructions: {
        business: '4011243',
        account: payment.account_number,
        amount: amount
      }
    });
    
  } catch (error) {
    console.error('❌ Paybill initiation error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Confirm Paybill payment (user clicks "I have paid")
app.post('/api/payments/paybill/confirm', authenticateToken, async (req, res) => {
  const { paymentId, confirmationCode } = req.body;
  
  try {
    console.log('💰 Confirming Paybill payment:', paymentId);
    
    // Get payment details
    const payment = await pool.query(
      `SELECT pp.*, u.full_name 
       FROM paybill_payments pp
       JOIN profiles u ON pp.user_id = u.id
       WHERE pp.id = $1`,
      [paymentId]
    );
    
    if (payment.rows.length === 0) {
      return res.status(404).json({ error: 'Payment not found' });
    }
    
    const payData = payment.rows[0];
    
    // Verify user owns this payment
    if (payData.user_id !== req.user.userId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    // Check if payment is already confirmed
    if (payData.status === 'confirmed') {
      return res.json({
        success: true,
        message: 'Payment already confirmed',
        alreadyConfirmed: true
      });
    }
    
    // Check if payment has expired
    if (new Date(payData.expires_at) < new Date()) {
      await pool.query(
        'UPDATE paybill_payments SET status = $1 WHERE id = $2',
        ['expired', paymentId]
      );
      return res.status(400).json({ error: 'Payment has expired. Please start a new deposit.' });
    }
    
    // In a real system, you would verify with M-PESA API here
    // For now, we'll simulate a successful confirmation
    
    // Update payment status
    await pool.query(
      `UPDATE paybill_payments 
       SET status = 'confirmed', 
           confirmed_at = NOW(),
           confirmation_code = $1
       WHERE id = $2`,
      [confirmationCode || `CONF-${Date.now()}`, paymentId]
    );
    
    // Update transaction status to completed
    await pool.query(
      `UPDATE transactions 
       SET status = 'completed', 
           completed_at = NOW(),
           description = 'Paybill deposit confirmed'
       WHERE id = $1`,
      [payData.transaction_id]
    );
    
    // Update wallet balance
    await pool.query(
      `UPDATE wallets 
       SET main_balance = main_balance + $1,
           lifetime_deposits = lifetime_deposits + $1,
           last_updated = NOW()
       WHERE user_id = $2`,
      [payData.amount, payData.user_id]
    );
    
    // Create notification (optional)
    console.log(`✅ Payment confirmed for user ${payData.user_id}: +KES ${payData.amount}`);
    
    res.json({
      success: true,
      message: 'Payment confirmed successfully',
      amount: payData.amount
    });
    
  } catch (error) {
    console.error('❌ Paybill confirmation error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Check Paybill payment status
app.get('/api/payments/paybill/status/:paymentId', authenticateToken, async (req, res) => {
  const { paymentId } = req.params;
  
  try {
    const payment = await pool.query(
      `SELECT pp.*, t.status as transaction_status
       FROM paybill_payments pp
       LEFT JOIN transactions t ON pp.transaction_id = t.id
       WHERE pp.id = $1`,
      [paymentId]
    );
    
    if (payment.rows.length === 0) {
      return res.status(404).json({ error: 'Payment not found' });
    }
    
    const payData = payment.rows[0];
    
    // Verify user owns this payment
    if (payData.user_id !== req.user.userId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    res.json({
      status: payData.status,
      amount: payData.amount,
      expiresAt: payData.expires_at,
      transactionStatus: payData.transaction_status
    });
    
  } catch (error) {
    console.error('❌ Paybill status error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== GAME BETTING ENDPOINTS ====================

// Place a game bet (Aviator/JetX)
app.post('/api/games/bet', authenticateToken, async (req, res) => {
  const { userId, gameType, stake, autoCashout } = req.body;
  
  try {
    console.log('🎲 Placing game bet:', { userId, gameType, stake });
    
    // Verify user
    if (req.user.userId !== userId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    // Validate stake
    if (stake < 10 || stake > 5000) {
      return res.status(400).json({ error: 'Stake must be between KES 10 and 5,000' });
    }
    
    // Check user balance
    const wallet = await pool.query(
      'SELECT main_balance FROM wallets WHERE user_id = $1',
      [userId]
    );
    
    if (wallet.rows.length === 0) {
      return res.status(404).json({ error: 'Wallet not found' });
    }
    
    const currentBalance = parseFloat(wallet.rows[0].main_balance);
    
    if (currentBalance < stake) {
      return res.status(400).json({ 
        error: 'Insufficient balance',
        available: currentBalance,
        required: stake
      });
    }
    
    // Start transaction
    await pool.query('BEGIN');
    
    // Create bet record
    const betResult = await pool.query(
      `INSERT INTO bets (
        user_id, 
        selections, 
        stake, 
        total_odds, 
        potential_winnings,
        status, 
        bet_type, 
        game_type,
        reference_number,
        created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
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
        `${gameType}-${Date.now()}-${Math.floor(Math.random() * 1000)}`
      ]
    );
    
    const betId = betResult.rows[0].id;
    
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
        user_id, type, amount, status, description, 
        reference, balance_before, balance_after
      ) VALUES ($1, 'bet', $2, 'completed', $3, $4, $5, $6)`,
      [
        userId,
        stake,
        `${gameType} bet placed`,
        `BET-${betId}`,
        currentBalance,
        currentBalance - stake
      ]
    );
    
    await pool.query('COMMIT');
    
    console.log(`✅ Bet placed: User ${userId} bet KES ${stake} on ${gameType}`);
    
    res.json({
      success: true,
      betId,
      message: 'Bet placed successfully',
      newBalance: currentBalance - stake
    });
    
  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('❌ Game bet error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Cashout from game
app.post('/api/games/cashout', authenticateToken, async (req, res) => {
  const { betId, userId, multiplier } = req.body;
  
  try {
    console.log('💰 Processing cashout:', { betId, userId, multiplier });
    
    // Verify user
    if (req.user.userId !== userId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    // Get bet details
    const bet = await pool.query(
      'SELECT * FROM bets WHERE id = $1 AND user_id = $2 AND status = $3',
      [betId, userId, 'pending']
    );
    
    if (bet.rows.length === 0) {
      return res.status(404).json({ error: 'Bet not found or already settled' });
    }
    
    const betData = bet.rows[0];
    const winAmount = betData.stake * multiplier;
    
    // Start transaction
    await pool.query('BEGIN');
    
    // Update bet
    await pool.query(
      `UPDATE bets 
       SET status = 'cashed_out', 
           cashout_multiplier = $1,
           actual_winnings = $2,
           settled_at = NOW()
       WHERE id = $3`,
      [multiplier, winAmount, betId]
    );
    
    // Get current balance
    const wallet = await pool.query(
      'SELECT main_balance FROM wallets WHERE user_id = $1',
      [userId]
    );
    
    const currentBalance = parseFloat(wallet.rows[0].main_balance);
    
    // Add winnings to wallet
    await pool.query(
      `UPDATE wallets 
       SET main_balance = main_balance + $1,
           lifetime_winnings = lifetime_winnings + $1,
           last_updated = NOW()
       WHERE user_id = $2`,
      [winAmount, userId]
    );
    
    // Create win transaction
    await pool.query(
      `INSERT INTO transactions (
        user_id, type, amount, status, description, 
        reference, balance_before, balance_after
      ) VALUES ($1, 'win', $2, 'completed', $3, $4, $5, $6)`,
      [
        userId,
        winAmount,
        `Cashed out at ${multiplier}x`,
        `WIN-${betId}`,
        currentBalance,
        currentBalance + winAmount
      ]
    );
    
    await pool.query('COMMIT');
    
    console.log(`✅ Cashout processed: User ${userId} won KES ${winAmount} at ${multiplier}x`);
    
    res.json({
      success: true,
      winAmount,
      message: `Cashed out at ${multiplier}x! You won KES ${winAmount}`,
      newBalance: currentBalance + winAmount
    });
    
  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('❌ Cashout error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/games/history/:gameType', async (req, res) => {
  const { gameType } = req.params;
  const limit = parseInt(req.query.limit) || 20;  // Removed 'as string'
  
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
