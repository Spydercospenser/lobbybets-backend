const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

async function checkTables() {
  try {
    console.log('🔍 Checking database tables...');
    
    // Check if bets table exists
    const betsTable = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'bets'
      );
    `);
    
    console.log('📊 Bets table exists:', betsTable.rows[0].exists);
    
    if (betsTable.rows[0].exists) {
      // Get bets table structure
      const betsStructure = await pool.query(`
        SELECT column_name, data_type 
        FROM information_schema.columns 
        WHERE table_name = 'bets'
        ORDER BY ordinal_position;
      `);
      
      console.log('\n📋 Bets table structure:');
      betsStructure.rows.forEach(col => {
        console.log(`   - ${col.column_name}: ${col.data_type}`);
      });
      
      // Count bets for your user
      const userBets = await pool.query(
        'SELECT COUNT(*) FROM bets WHERE user_id = $1',
        ['b778d6eb-25af-48a6-9364-8a993118a56d']
      );
      console.log(`\n🎲 Bets for user b778d6eb-25af-48a6-9364-8a993118a56d: ${userBets.rows[0].count}`);
    }
    
    // Check other tables
    const tables = ['profiles', 'wallets', 'transactions', 'mpesa_transactions', 'leagues', 'matches'];
    
    console.log('\n📊 Other tables:');
    for (const table of tables) {
      const result = await pool.query(`
        SELECT EXISTS (
          SELECT FROM information_schema.tables 
          WHERE table_name = $1
        );
      `, [table]);
      
      console.log(`   - ${table}: ${result.rows[0].exists ? '✅' : '❌'}`);
    }
    
  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    await pool.end();
  }
}

checkTables();
