const express = require('express');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const db = require('./config/database');
const { hashPassword, verifyPassword, requireAuth } = require('./middleware/auth');

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'nayotama-secret-key-2025',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000, // 24 jam
    httpOnly: true
  }
}));

// =========================
// PUBLIC ROUTES
// =========================

// Homepage - Generate API Key
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Generate API Key dengan User Registration
app.post('/create', async (req, res) => {
  try {
    const { firstName, lastName, email } = req.body;

    // Validasi input
    if (!firstName || !lastName || !email) {
      return res.status(400).json({
        success: false,
        message: 'Semua field harus diisi (First Name, Last Name, Email)'
      });
    }

    // Validasi email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: 'Format email tidak valid'
      });
    }

    // Generate API Key
    const randomKey = crypto.randomBytes(32).toString('hex');
    const fullApiKey = `sk-itumy-v1-api_${randomKey}`;
 
    // Insert API Key
    const apiKeyQuery = `
      INSERT INTO api_keys (api_key, prefix, is_active, usage_count, out_of_date) 
      VALUES (?, ?, ?, ?, ?)
    `;
    
    const [apiKeyResult] = await db.execute(apiKeyQuery, [
      fullApiKey,
      'sk-itumy-v1-api_',
      true,
      0,
      false
    ]);
    
    const apiKeyId = apiKeyResult.insertId;

    // Insert User
    const userQuery = `
      INSERT INTO users (first_name, last_name, email, api_key_id) 
      VALUES (?, ?, ?, ?)
    `;
    
    await db.execute(userQuery, [
      firstName,
      lastName,
      email,
      apiKeyId
    ]);
    
    res.json({
      success: true,
      apiKey: fullApiKey,
      message: 'API Key berhasil dibuat dan user berhasil didaftarkan',
      user: {
        firstName,
        lastName,
        email
      }
    });
  } catch (error) {
    console.error('Error creating API key:', error);

    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({
        success: false,
        message: 'API Key atau Email sudah terdaftar'
      });
    }
    
    res.status(500).json({
      success: false,
      message: 'Gagal membuat API Key',
      error: error.message
    });
  }
});

// Check API Key
app.post('/checkapi', async (req, res) => {
  try {
    const { apikey } = req.body;

    if (!apikey) {
      return res.status(400).json({
        success: false,
        valid: false,
        message: 'API key tidak boleh kosong'
      });
    }

    if (!apikey.startsWith('sk-itumy-v1-api_')) {
      return res.status(400).json({
        success: false,
        valid: false,
        message: 'Format API key tidak valid'
      });
    }

    const query = `
      SELECT * FROM api_keys 
      WHERE api_key = ? 
      LIMIT 1
    `;
    
    const [rows] = await db.execute(query, [apikey]);
    
    if (rows.length === 0) {
      return res.status(401).json({
        success: false,
        valid: false,
        message: 'API key tidak ditemukan',
        apikey: apikey
      });
    }
    
    const apiKeyData = rows[0];

    if (!apiKeyData.is_active || apiKeyData.out_of_date) {
      return res.status(401).json({
        success: false,
        valid: false,
        message: 'API key sudah tidak aktif',
        apikey: apikey,
        isActive: false
      });
    }

    // Update usage count dan last used
    const updateQuery = `
      UPDATE api_keys 
      SET usage_count = usage_count + 1, 
          last_used_at = CURRENT_TIMESTAMP 
      WHERE api_key = ?
    `;
    
    await db.execute(updateQuery, [apikey]);

    res.json({
      success: true,
      valid: true,
      message: 'API key valid',
      apikey: apikey,
      prefix: apiKeyData.prefix,
      createdAt: apiKeyData.created_at,
      usageCount: apiKeyData.usage_count + 1,
      lastUsedAt: new Date(),
      isActive: apiKeyData.is_active
    });
    
  } catch (error) {
    console.error('Error checking API key:', error);
    res.status(500).json({
      success: false,
      valid: false,
      message: 'Terjadi kesalahan server',
      error: error.message
    });
  }
});

// =========================
// ADMIN AUTH ROUTES
// =========================

// Admin Register Page
app.get('/admin/register', (req, res) => {
  if (req.session.adminId) {
    return res.redirect('/admin/dashboard');
  }
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// Admin Login Page
app.get('/admin/login', (req, res) => {
  if (req.session.adminId) {
    return res.redirect('/admin/dashboard');
  }
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Admin Register
app.post('/admin/register', hashPassword, async (req, res) => {
  try {
    const { email, hashedPassword } = req.body;

    if (!email || !hashedPassword) {
      return res.status(400).json({
        success: false,
        message: 'Email dan password harus diisi'
      });
    }

    const query = `
      INSERT INTO admins (email, password) 
      VALUES (?, ?)
    `;
    
    await db.execute(query, [email, hashedPassword]);
    
    res.json({
      success: true,
      message: 'Admin berhasil terdaftar, silakan login',
      redirectTo: '/admin/login'
    });
  } catch (error) {
    console.error('Error registering admin:', error);
    
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({
        success: false,
        message: 'Email sudah terdaftar'
      });
    }
    
    res.status(500).json({
      success: false,
      message: 'Gagal mendaftar',
      error: error.message
    });
  }
});

// Admin Login
app.post('/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email dan password harus diisi'
      });
    }

    const query = `SELECT * FROM admins WHERE email = ? LIMIT 1`;
    const [rows] = await db.execute(query, [email]);
    
    if (rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Email atau password salah'
      });
    }
    
    const admin = rows[0];
    const isPasswordValid = await verifyPassword(password, admin.password);
    
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Email atau password salah'
      });
    }

    // Set session
    req.session.adminId = admin.id;
    req.session.adminEmail = admin.email;
    
    res.json({
      success: true,
      message: 'Login berhasil',
      redirectTo: '/admin/dashboard'
    });
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({
      success: false,
      message: 'Gagal login',
      error: error.message
    });
  }
});

// Admin Logout
app.post('/admin/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({
        success: false,
        message: 'Gagal logout'
      });
    }
    res.json({
      success: true,
      message: 'Logout berhasil',
      redirectTo: '/admin/login'
    });
  });
});

// =========================
// ADMIN DASHBOARD ROUTES
// =========================

// Dashboard Page
app.get('/admin/dashboard', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Get All Users and API Keys for Dashboard
app.get('/admin/users-apikeys', requireAuth, async (req, res) => {
  try {
    const query = `
      SELECT 
        u.id as user_id,
        u.first_name,
        u.last_name,
        u.email,
        ak.id as api_key_id,
        ak.api_key,
        ak.is_active,
        ak.out_of_date,
        ak.usage_count,
        ak.created_at,
        ak.last_used_at,
        CASE 
          WHEN ak.last_used_at IS NULL THEN 'Never Used'
          WHEN TIMESTAMPDIFF(DAY, ak.last_used_at, NOW()) >= 30 THEN 'Inactive'
          ELSE 'Active'
        END as status
      FROM users u
      LEFT JOIN api_keys ak ON u.api_key_id = ak.id
      ORDER BY u.id DESC
    `;
    
    const [rows] = await db.execute(query);
    
    res.json({
      success: true,
      total: rows.length,
      data: rows
    });
  } catch (error) {
    console.error('Error fetching data:', error);
    res.status(500).json({
      success: false,
      message: 'Gagal mengambil data',
      error: error.message
    });
  }
});

// Delete API Key
app.delete('/admin/apikeys/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Delete user first (karena foreign key)
    await db.execute('DELETE FROM users WHERE api_key_id = ?', [id]);
    
    // Delete API key
    const query = `DELETE FROM api_keys WHERE id = ?`;
    const [result] = await db.execute(query, [id]);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: 'API key tidak ditemukan'
      });
    }
    
    res.json({
      success: true,
      message: 'API key dan user terkait berhasil dihapus'
    });
  } catch (error) {
    console.error('Error deleting API key:', error);
    res.status(500).json({
      success: false,
      message: 'Gagal menghapus API key',
      error: error.message
    });
  }
});

// Update status out_of_date otomatis (cron job sederhana)
setInterval(async () => {
  try {
    const query = `
      UPDATE api_keys 
      SET out_of_date = TRUE 
      WHERE last_used_at IS NOT NULL 
      AND TIMESTAMPDIFF(DAY, last_used_at, NOW()) >= 30
      AND out_of_date = FALSE
    `;
    await db.execute(query);
  } catch (error) {
    console.error('Error updating out_of_date status:', error);
  }
}, 60 * 60 * 1000); // Cek setiap 1 jam

app.listen(port, () => {
  console.log(`🚀 Server berjalan di http://localhost:${port}`);
  console.log(`📊 Admin Dashboard: http://localhost:${port}/admin/login`);
});