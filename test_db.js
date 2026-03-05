const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

async function testConnection() {
  try {
    const client = await pool.connect();
    console.log('✅ Connected to database successfully!');
    
    const result = await client.query('SELECT NOW() as current_time');
    console.log('📅 Server time:', result.rows[0].current_time);
    
    const tables = await client.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
      ORDER BY table_name
    `);
    
    console.log('\n📊 Tables created:');
    tables.rows.forEach(row => {
      console.log(`   - ${row.table_name}`);
    });
    
    console.log(`\n📈 Total tables: ${tables.rows.length}`);
    
    client.release();
    await pool.end();
  } catch (err) {
    console.error('❌ Database connection failed:', err.message);
    process.exit(1);
  }
}

testConnection();
