// createadmin.js
const { MongoClient } = require('mongodb');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');

dotenv.config();

const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri);

async function createAdmin() {
  try {
    await client.connect();
    const db = client.db('MugoMarbles');
    const users = db.collection('users');

    // Set the admin account details:
    const adminUsername = 'admin'; // choose your admin username
    const adminPassword = 'MugoMarbles123!'; // choose a secure password

    // Check if an admin account already exists:
    const existingAdmin = await users.findOne({ username: adminUsername });
    if (existingAdmin) {
      console.log('Admin account already exists.');
      return;
    }

    const hashedPassword = await bcrypt.hash(adminPassword, 10);
    const adminUser = {
      username: adminUsername,
      password: hashedPassword,
      role: 'admin',
      // You may add location if needed or leave it blank
      location: { county: '', workArea: '' }
    };

    await users.insertOne(adminUser);
    console.log('Admin account created successfully.');
  } catch (error) {
    console.error('Error creating admin account:', error);
  } finally {
    await client.close();
  }
}

createAdmin();
