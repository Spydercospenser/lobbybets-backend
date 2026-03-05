#!/bin/bash

# LobbyBets Kenya - Database Setup Script
# Save this as setup_database.sh and run: sudo bash setup_database.sh

set -e

echo "========================================="
echo "LobbyBets Kenya Database Setup"
echo "========================================="

# Configuration
DB_NAME="lobbybets"
DB_USER="lobbybets_user"
DB_PASSWORD="LobbyBets@2024Secure!"
BACKEND_DIR="/home/qml/projects/house-hunt-app/LobbyBets-Kenya/lobbybets-backend"
SQL_DIR="$BACKEND_DIR/sql"

# M-PESA Credentials (PRODUCTION)
MPESA_CONSUMER_KEY="EiTjMcrIYbxBJY1G7UiNVu62YwxVEfEQ1qdTA9u7uY9nhOBP"
MPESA_CONSUMER_SECRET="GaPQ3RxOpJnd03Sx96PMX1igq9nDSBChFjGky0f1QNZOx9jALtPt07v9GmpHCMoc"
MPESA_SHORTCODE="4011243"
MPESA_PASSKEY="ed0f022db9398b8082f6c4114a8bcb2d25a9685c2383790947a5aa76cd5c30e5"
MPESA_ENVIRONMENT="production"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
print_info() { echo -e "${YELLOW}📌 $1${NC}"; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root (use sudo)"
   exit 1
fi

# Check if SQL directory exists
if [ ! -d "$SQL_DIR" ]; then
    print_error "SQL directory not found at $SQL_DIR"
    exit 1
fi

# Fix permissions
print_info "Fixing permissions on SQL files..."
chmod -R 755 "$SQL_DIR"
chown -R postgres:postgres "$SQL_DIR" 2>/dev/null || true
print_success "Permissions fixed"

# Check PostgreSQL
if ! systemctl is-active --quiet postgresql; then
    print_info "Starting PostgreSQL..."
    systemctl start postgresql
    systemctl enable postgresql
fi

# Create user if not exists
print_info "Creating database user..."
sudo -u postgres psql << EOF
DO
\$do\$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '$DB_USER') THEN
      CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';
   END IF;
END
\$do\$;
EOF

# Drop and recreate database
print_info "Resetting database..."
sudo -u postgres psql << EOF
DROP DATABASE IF EXISTS $DB_NAME;
CREATE DATABASE $DB_NAME OWNER $DB_USER;
EOF

# Grant privileges
print_info "Granting privileges..."
sudo -u postgres psql -d $DB_NAME << EOF
GRANT ALL ON SCHEMA public TO $DB_USER;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO $DB_USER;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO $DB_USER;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO $DB_USER;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO $DB_USER;
EOF

# Run each SQL file individually
print_info "Running database setup scripts..."

cd "$SQL_DIR"

for file in 00_setup.sql 01_schema.sql 02_seed_data.sql 03_indexes.sql 04_functions_triggers.sql 05_views.sql 06_rls_policies.sql; do
    if [ -f "$file" ]; then
        print_info "Running $file..."
        if sudo -u postgres psql -d $DB_NAME -f "$file"; then
            print_success "$file completed"
        else
            print_error "$file failed"
            exit 1
        fi
    else
        print_error "File $file not found"
        exit 1
    fi
done

print_success "Database setup completed successfully!"

# Create .env file with M-PESA credentials
print_info "Creating .env file with M-PESA credentials..."

# Generate JWT Secret
JWT_SECRET=$(openssl rand -base64 32)

cat > "$BACKEND_DIR/.env" << ENVEOF
# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASSWORD
DATABASE_URL=postgresql://$DB_USER:$DB_PASSWORD@localhost:5432/$DB_NAME

# JWT Configuration
JWT_SECRET=$JWT_SECRET
JWT_EXPIRES_IN=7d

# Server Configuration
PORT=3000
NODE_ENV=production
API_URL=http://localhost:3000

# M-PESA Configuration (PRODUCTION)
MPESA_CONSUMER_KEY=$MPESA_CONSUMER_KEY
MPESA_CONSUMER_SECRET=$MPESA_CONSUMER_SECRET
MPESA_SHORTCODE=$MPESA_SHORTCODE
MPESA_PASSKEY=$MPESA_PASSKEY
MPESA_ENVIRONMENT=production

# M-PESA Paybill Details
MPESA_PAYBILL=$MPESA_SHORTCODE
MPESA_ACCOUNT_NUMBER=Lobby

# Frontend URL
FRONTEND_URL=http://localhost:8081
ENVEOF

print_success ".env file created with M-PESA production credentials"

# Create M-PESA test script
print_info "Creating M-PESA test script..."

cat > "$BACKEND_DIR/test_mpesa.js" << 'MPESATEST'
const axios = require('axios');
require('dotenv').config();

console.log('=========================================');
console.log('🔍 Testing M-PESA Configuration');
console.log('=========================================');
console.log('📱 Environment:', process.env.MPESA_ENVIRONMENT);
console.log('📱 Shortcode:', process.env.MPESA_SHORTCODE);
console.log('📱 Paybill:', process.env.MPESA_PAYBILL);
console.log('📱 Account:', process.env.MPESA_ACCOUNT_NUMBER);
console.log('📱 Consumer Key:', process.env.MPESA_CONSUMER_KEY ? '✅ Set' : '❌ Missing');
console.log('📱 Consumer Secret:', process.env.MPESA_CONSUMER_SECRET ? '✅ Set' : '❌ Missing');
console.log('📱 Passkey:', process.env.MPESA_PASSKEY ? '✅ Set' : '❌ Missing');
console.log('=========================================');

// Test OAuth token generation
async function testMpesaAuth() {
    try {
        const auth = Buffer.from(
            `${process.env.MPESA_CONSUMER_KEY}:${process.env.MPESA_CONSUMER_SECRET}`
        ).toString('base64');
        
        console.log('🔄 Requesting access token...');
        
        const response = await axios.get(
            'https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials',
            { 
                headers: { 
                    Authorization: `Basic ${auth}` 
                } 
            }
        );
        
        if (response.data && response.data.access_token) {
            console.log('✅ M-PESA Authentication successful!');
            console.log('🔑 Access Token:', response.data.access_token.substring(0, 20) + '...');
            return true;
        }
    } catch (error) {
        console.error('❌ M-PESA Authentication failed:');
        if (error.response) {
            console.error('   Status:', error.response.status);
            console.error('   Data:', error.response.data);
        } else {
            console.error('   Error:', error.message);
        }
        return false;
    }
}

testMpesaAuth().then(success => {
    if (success) {
        console.log('=========================================');
        console.log('✅ M-PESA is configured correctly!');
        console.log('=========================================');
        console.log('📝 Payment Instructions for Users:');
        console.log('   1. Go to M-PESA');
        console.log('   2. Lipa na M-PESA');
        console.log('   3. Paybill');
        console.log(`   4. Business Number: ${process.env.MPESA_PAYBILL}`);
        console.log(`   5. Account Number: ${process.env.MPESA_ACCOUNT_NUMBER}`);
        console.log('   6. Enter Amount');
        console.log('   7. Enter PIN');
        console.log('=========================================');
    } else {
        console.log('=========================================');
        console.log('❌ M-PESA configuration needs review');
        console.log('=========================================');
    }
    process.exit(0);
});
MPESATEST

print_success "M-PESA test script created"

# Create database test script
print_info "Creating database test script..."

cat > "$BACKEND_DIR/test_db.js" << 'TESTEOF'
const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

console.log('🔍 Testing database connection...');

pool.query('SELECT NOW() as time', (err, res) => {
  if (err) {
    console.error('❌ Connection failed:', err.message);
    process.exit(1);
  }
  console.log('✅ Database connected successfully!');
  console.log('📅 Server time:', res.rows[0].time);
  
  // Check if tables exist
  pool.query(`
    SELECT table_name 
    FROM information_schema.tables 
    WHERE table_schema = 'public'
    ORDER BY table_name
  `, (err, res) => {
    if (err) {
      console.error('❌ Failed to list tables:', err.message);
    } else {
      console.log('📊 Tables created:');
      res.rows.forEach(row => {
        console.log(`   - ${row.table_name}`);
      });
    }
    
    // Check if profiles table has data
    pool.query('SELECT COUNT(*) FROM profiles', (err, res) => {
      if (err) {
        console.log('ℹ️  No profiles table or empty');
      } else {
        console.log(`👤 Profiles in database: ${res.rows[0].count}`);
      }
      process.exit(0);
    });
  });
});
TESTEOF

print_success "Test script created"

# Install dependencies if needed
if [ ! -d "$BACKEND_DIR/node_modules" ]; then
    print_info "Installing Node.js dependencies..."
    cd "$BACKEND_DIR"
    npm init -y
    npm install pg dotenv express cors bcrypt jsonwebtoken axios
fi

# Test database connection
print_info "Testing database connection..."
cd "$BACKEND_DIR"
if node test_db.js; then
    print_success "Database connection test passed!"
else
    print_error "Database connection test failed"
    exit 1
fi

# Test M-PESA configuration (optional - doesn't fail if it doesn't work)
print_info "Testing M-PESA configuration..."
node test_mpesa.js

print_success "
=========================================
🎉 LOBBYBETS KENYA DATABASE SETUP COMPLETE!
=========================================

📊 Database: $DB_NAME
👤 User: $DB_USER
📍 Host: localhost:5432

💰 M-PESA Configuration (PRODUCTION):
   📱 Paybill: $MPESA_SHORTCODE
   📱 Account: Lobby
   📱 Environment: Production

📝 Payment Instructions for Users:
   1. Go to M-PESA
   2. Lipa na M-PESA
   3. Paybill
   4. Business Number: $MPESA_SHORTCODE
   5. Account Number: Lobby
   6. Enter Amount
   7. Enter PIN

Next steps:
1. Start your backend server:
   cd $BACKEND_DIR && node server.js

2. Test M-PESA payment:
   curl -X POST http://localhost:3000/api/mpesa/stkpush \\
     -H \"Content-Type: application/json\" \\
     -H \"Authorization: Bearer YOUR_TOKEN\" \\
     -d '{\"userId\":\"USER_ID\",\"phoneNumber\":\"0712345678\",\"amount\":100}'

3. Your profile screen should now work!

Happy coding! 🚀"
