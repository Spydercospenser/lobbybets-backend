const fetch = require('node-fetch');

async function debugLogin() {
  console.log('1️⃣ Testing admin login...\n');
  
  try {
    const response = await fetch('http://localhost:3000/api/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'kiptuiamos001@gmail.com',
        password: 'Admin123#'
      })
    });
    
    console.log('📡 Response status:', response.status);
    
    const text = await response.text();
    console.log('📦 Raw response:', text);
    
    try {
      const data = JSON.parse(text);
      console.log('\n📊 Parsed response:', JSON.stringify(data, null, 2));
    } catch (e) {
      console.log('❌ Could not parse response as JSON');
    }
    
  } catch (error) {
    console.error('❌ Connection error:', error.message);
  }
}

debugLogin();
