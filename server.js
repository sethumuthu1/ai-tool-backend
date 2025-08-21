// server.js - Complete Express Server for User Registration & Admin Approval System
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const router = express.Router();
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const path = require('path');
require('dotenv').config();
const { logAudit } = require('./utils/auditLogger'); // New audit utility
const axios = require('axios');

const { getSecretsFromVault } = require('./config/vault');

const vault = require('node-vault')({
  endpoint: process.env.VAULT_ADDR,
  token: process.env.VAULT_TOKEN,
});

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Serve static files (if needed)
app.use(express.static(path.join(__dirname, 'public')));


// Database configuration
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'root',
  database: process.env.DB_NAME || 'ai_system',
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  multipleStatements: true
};

// Email configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// JWT Secret with fallback
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_key_change_in_production_2024';

// Database connection pool
let db;

async function initializeDatabase() {
  try {
    // First, create connection without specifying database to create it
    const tempConfig = { ...dbConfig };
    delete tempConfig.database;
    
    let tempConnection;
    try {
      tempConnection = await mysql.createConnection(tempConfig);
      
      // Create database using regular query (not prepared statement)
      await tempConnection.query(`CREATE DATABASE IF NOT EXISTS \`${dbConfig.database}\``);
      console.log(`✅ Database '${dbConfig.database}' created/verified`);
      
    } catch (dbError) {
      console.log('ℹ️  Database might already exist or creation failed:', dbError.message);
    } finally {
      if (tempConnection) {
        await tempConnection.end();
      }
    }
    
    // Now create connection pool with the database
    db = mysql.createPool(dbConfig);
    
    // Test connection
    const connection = await db.getConnection();
    console.log('✅ Connected to MySQL database');
    connection.release();
    
    // Create tables
    await createTables();
    
  } catch (error) {
    console.error('❌ Database initialization failed:', error.message);
    
    // If it's a connection error, provide helpful info
    if (error.code === 'ECONNREFUSED') {
      console.error('💡 Make sure MySQL is running on your system');
      console.error('💡 Check if your MySQL credentials in .env are correct');
    }
    
    process.exit(1);
  }
}

// Create tables (separated from database creation)
async function createTables() {
  try {
    // Create users table
    await db.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT PRIMARY KEY AUTO_INCREMENT,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        first_name VARCHAR(100) NOT NULL,
        last_name VARCHAR(100) NOT NULL,
        phone VARCHAR(20),
        organization VARCHAR(255),
        status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
        auth_key VARCHAR(255) UNIQUE,
        approval_token VARCHAR(255) UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_email (email),
        INDEX idx_status (status),
        INDEX idx_approval_token (approval_token)
      ) ENGINE=InnoDB
    `);

    // Create admins table
    await db.execute(`
      CREATE TABLE IF NOT EXISTS admins (
        id INT PRIMARY KEY AUTO_INCREMENT,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL,
        role ENUM('admin', 'super_admin') DEFAULT 'admin',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB
    `);

    // Insert default admin if not exists
    const adminPassword = await bcrypt.hash('admin123', 10);
    await db.execute(`
      INSERT IGNORE INTO admins (email, password, name, role) VALUES 
      ('admin@company.com', ?, 'System Admin', 'super_admin')
    `, [adminPassword]);

    console.log('✅ Database tables created/verified successfully');
    
  } catch (error) {
    console.error('❌ Error creating database tables:', error.message);
    throw error;
  }
}

// Utility functions
function generateAuthKey() {
  return crypto.randomBytes(32).toString('hex');
}

function generateApprovalToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Email Send to Admin for Approval
async function sendAdminApprovalEmail(userData, approvalToken) {
  try {
    const pendingUrl = `http://localhost:5173/organization/dashboard`; // You can replace with your actual URL

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: process.env.ADMIN_EMAIL || 'admin@company.com',
      subject: '📝 New User Registration - Approval Required',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; background-color: #f4f4f4; padding: 20px; border-radius: 10px;">
          <h2 style="color: #333;">New User Registration</h2>
          <p>A new user has registered and requires admin approval:</p>
          
          <table style="width: 100%; margin: 20px 0; border-collapse: collapse;">
            <tr>
              <td style="padding: 8px; font-weight: bold;">Name:</td>
              <td style="padding: 8px;">${userData.first_name} ${userData.last_name}</td>
            </tr>
            <tr>
              <td style="padding: 8px; font-weight: bold;">Email:</td>
              <td style="padding: 8px;">${userData.email}</td>
            </tr>
            <tr>
              <td style="padding: 8px; font-weight: bold;">Phone:</td>
              <td style="padding: 8px;">${userData.phone || 'N/A'}</td>
            </tr>
            <tr>
              <td style="padding: 8px; font-weight: bold;">Organization:</td>
              <td style="padding: 8px;">${userData.organization || 'N/A'}</td>
            </tr>
            <tr>
              <td style="padding: 8px; font-weight: bold;">Registered:</td>
              <td style="padding: 8px;">${new Date().toLocaleString()}</td>
            </tr>
          </table>

          <div style="text-align: center; margin: 30px 0;">
            <a href="${pendingUrl}" 
               style="background-color: #28a745; color: white; padding: 12px 25px; border-radius: 5px; text-decoration: none; font-weight: bold;">
              🔓 Go to Admin Portal to Review
            </a>
          </div>

          <p style="font-size: 12px; color: #555;">Or visit manually: <a href="${pendingUrl}">${pendingUrl}</a></p>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log('✅ Admin approval email sent successfully');
    
  } catch (error) {
    console.error('❌ Error sending admin approval email:', error.message);
  }
}


// Email send to user upon approval confimation
async function sendUserApprovalNotification(userData) {
  try {
    const loginUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/login`;
    
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: userData.email,
      subject: '🎉 Account Approved - Welcome!',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%); padding: 20px; text-align: center;">
            <h1 style="color: white; margin: 0;">Account Approved! 🎉</h1>
          </div>
          
          <div style="padding: 30px; background: #f9f9f9;">
            <p style="font-size: 18px; color: #333;">Dear ${userData.first_name},</p>
            <p style="font-size: 16px; color: #333;">Great news! Your account has been approved by the admin. You can now access the system.</p>
            
            <div style="background: white; padding: 20px; border-radius: 8px; margin: 20px 0;">
              <p style="font-weight: bold; color: #333; margin: 0 0 10px 0;">Your Authentication Key:</p>
              <code style="background: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace; word-break: break-all; display: block;">${userData.auth_key}</code>
              <p style="font-size: 12px; color: #666; margin: 10px 0 0 0;">Keep this key secure - you'll need it to access your account.</p>
            </div>
            
            <div style="text-align: center; margin: 30px 0;">
              <a href="${loginUrl}" 
                 style="background: linear-gradient(135deg, #2196F3 0%, #1976D2 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
                🚀 Login Now
              </a>
            </div>
            
            <p style="font-size: 14px; color: #666; text-align: center;">Welcome aboard! We're excited to have you.</p>
          </div>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log('✅ User approval notification sent successfully');
    
  } catch (error) {
    console.error('❌ Error sending user approval notification:', error.message);
    // Don't throw error, just log it
  }
}

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const authHeader = req.header('Authorization');
  const token = authHeader && authHeader.startsWith('Bearer ') 
    ? authHeader.substring(7) 
    : null;
  
  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Access denied. No token provided.'
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Token expired. Please login again.'
      });
    }
    
    res.status(401).json({
      success: false,
      message: 'Invalid token'
    });
  }
};

// Error handling middleware
const errorHandler = (err, req, res, next) => {
  console.error('Error:', err);
  
  if (err.code === 'ER_DUP_ENTRY') {
    return res.status(400).json({
      success: false,
      message: 'Email already exists'
    });
  }
  
  res.status(500).json({
    success: false,
    message: 'Internal server error'
  });
};

// Routes

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

app.post("/api/auth/register", async (req, res) => {
  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();

    const { email, password, first_name, last_name, phone, organization } = req.body;

    // Validation...
    if (!email || !password || !first_name || !last_name) {
      return res.status(400).json({ success: false, message: "Required fields missing" });
    }

    const [existingUser] = await connection.execute("SELECT id FROM users WHERE email = ?", [email.toLowerCase()]);
    if (existingUser.length > 0) {
      return res.status(400).json({ success: false, message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const approvalToken = generateApprovalToken();

    const [result] = await connection.execute(
      `INSERT INTO users (email, password, first_name, last_name, phone, organization, approval_token) 
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [email.toLowerCase(), hashedPassword, first_name, last_name, phone, organization, approvalToken]
    );

    // Write to Vault
    await vault.write(`kv/data/pending-users/${email.toLowerCase()}`, {
      data: { approved: false, token: approvalToken },
    });

    // ✅ LOG TO AUDIT TABLE HERE
    await logAudit(connection, 'register', email.toLowerCase(), 'user', true, 'User registered, pending approval');

    await connection.commit();

    // Send email
    sendAdminApprovalEmail({ email, first_name, last_name, phone, organization }, approvalToken).catch(console.error);

    res.status(201).json({
      success: true,
      message: "Registration successful. Awaiting admin approval.",
      userId: result.insertId,
    });

  } catch (error) {
    await connection.rollback();
    console.error("Registration error:", error);

    // ❌ Log failure to audit too
    await logAudit(connection, 'register', req.body.email || 'unknown', 'user', false, 'Registration failed');

    res.status(500).json({ success: false, message: "Registration failed" });
  } finally {
    connection.release();
  }
});




app.post("/api/groq", authenticateToken, async (req, res) => {
  const { messages, session_id } = req.body;
  const user = req.user;

  try {
    const response = await axios.post(
      "https://api.groq.com/openai/v1/chat/completions",
      {
        model: "llama3-8b-8192",
        messages,
        temperature: 0.7,
        max_tokens: 1024,
      },
      {
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${process.env.GROQ_API_KEY}`,
        },
      }
    );

    const reply = response.data.choices[0]?.message?.content || "No response";
    const lastUserMessage = messages[messages.length - 1]?.content || "";

    // Save chat to DB with session_id
    await db.execute(
      `INSERT INTO chat_history (user_id, user_email, user_type, query, response, session_id)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [user.id, user.email, user.userType, lastUserMessage, reply, session_id]
    );

    res.json({ reply });
  } catch (error) {
    console.error("Groq API Error:", error.response?.data || error.message);
    res.status(500).json({ error: "Groq API error." });
  }
});





app.get("/api/chat/sessions", authenticateToken, async (req, res) => {
  const { id: user_id } = req.user;

  try {
    const [rows] = await db.execute(
      `SELECT session_id, MAX(created_at) as last_updated 
       FROM chat_history 
       WHERE user_id = ?
       GROUP BY session_id
       ORDER BY last_updated DESC`,
      [user_id]
    );

    res.json({ sessions: rows });
  } catch (err) {
    console.error("Fetch sessions failed:", err.message);
    res.status(500).json({ message: "Failed to fetch sessions" });
  }
});





app.get("/api/chat/session/:sessionId", authenticateToken, async (req, res) => {
  const { id: user_id } = req.user;
  const { sessionId } = req.params;

  try {
    const [rows] = await db.execute(
      `SELECT query, response, created_at
       FROM chat_history
       WHERE user_id = ? AND session_id = ?
       ORDER BY created_at ASC`,
      [user_id, sessionId]
    );

    const messages = [];

    for (const row of rows) {
      messages.push({ role: "user", content: row.query });
      messages.push({ role: "assistant", content: row.response });
    }

    res.json({ success: true, messages });
  } catch (err) {
    console.error("Fetch session messages failed:", err.message);
    res.status(500).json({ message: "Failed to fetch session messages" });
  }
});














// === User Login ===
const MAX_ATTEMPTS = 3;
const BLOCK_DURATION_MINUTES = 1;

// === Authenticate JWT middleware ===
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(403);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// === Login Route ===
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log('Login attempt:', email);

    if (!email || !password) {
      await db.execute(
        'INSERT INTO audit_logs (event_type, user_email, user_type, success, message) VALUES (?, ?, ?, ?, ?)',
        ['login', email || 'unknown', 'user', false, 'Email and password required']
      );
      return res.status(400).json({ success: false, message: 'Email and password are required' });
    }

    let [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email.toLowerCase()]);
    let userType = 'user';

    if (rows.length === 0) {
      [rows] = await db.execute('SELECT * FROM organizations WHERE email = ?', [email.toLowerCase()]);
      userType = 'organization';

      if (rows.length === 0) {
        console.log('No matching user or organization found');
        await db.execute(
          'INSERT INTO audit_logs (event_type, user_email, user_type, success, message) VALUES (?, ?, ?, ?, ?)',
          ['login', email, 'user', false, 'Invalid email or password']
        );
        return res.status(401).json({ success: false, message: 'Invalid email or password' });
      }
    }

    const user = rows[0];
    console.log(`Found ${userType}:`, user);

    // Check user status (only for users)
    if (userType === 'user' && user.status === 'pending') {
      await db.execute(
        'INSERT INTO audit_logs (event_type, user_email, user_type, success, message) VALUES (?, ?, ?, ?, ?)',
        ['login', email, userType, false, 'Account not approved']
      );
      return res.status(403).json({
        success: false,
        message: 'Your account is not yet approved. Please wait for approval.',
      });
    }

    // Handle lock logic for organizations
    if (userType === 'organization') {
      const now = new Date();
      const blockWindowStart = new Date(now.getTime() - BLOCK_DURATION_MINUTES * 60 * 1000);
      const lastFailed = user.last_failed_at ? new Date(user.last_failed_at) : null;

      if (
        user.failed_attempts >= MAX_ATTEMPTS &&
        lastFailed &&
        lastFailed >= blockWindowStart
      ) {
        const remainingMinutes = Math.ceil(
          (lastFailed.getTime() + BLOCK_DURATION_MINUTES * 60 * 1000 - now.getTime()) / 60000
        );

        await db.execute(
          'INSERT INTO audit_logs (event_type, user_email, user_type, success, message) VALUES (?, ?, ?, ?, ?)',
          ['login', email, userType, false, `Account locked for ${remainingMinutes} minutes`]
        );

        return res.status(403).json({
          success: false,
          message: `Account locked. Try again in ${remainingMinutes} minute(s).`,
        });
      }
    }

    // Verify password
    const passwordMatch = await bcrypt.compare(password, user.password);
    console.log('Password match:', passwordMatch);

    if (!passwordMatch) {
      if (userType === 'organization') {
        await db.execute(
          'UPDATE organizations SET failed_attempts = failed_attempts + 1, last_failed_at = CURRENT_TIMESTAMP WHERE id = ?',
          [user.id]
        );
      }

      await db.execute(
        'INSERT INTO audit_logs (event_type, user_email, user_type, success, message) VALUES (?, ?, ?, ?, ?)',
        ['login', email, userType, false, 'Invalid password']
      );

      return res.status(401).json({ success: false, message: 'Invalid email or password' });
    }

    // Reset failed attempts if organization
    if (userType === 'organization') {
      await db.execute(
        'UPDATE organizations SET failed_attempts = 0, last_failed_at = NULL WHERE id = ?',
        [user.id]
      );
    }

    // Generate JWT token
    const tokenPayload = { id: user.id, email: user.email, userType };
    const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, {
      expiresIn: '24h',
      issuer: 'user-approval-system',
    });

    // Update last login timestamp
    await db.execute(
      userType === 'user'
        ? 'UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = ?'
        : 'UPDATE organizations SET updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [user.id]
    );

    // Prepare user data excluding password
    const userData = {
      id: user.id,
      email: user.email,
      first_name: user.first_name || null,
      last_name: user.last_name || null,
      phone: user.phone || null,
      organization: user.organization || null,
      status: user.status || null,
      userType,
    };

    // Log success
    await db.execute(
      'INSERT INTO audit_logs (event_type, user_email, user_type, success, message) VALUES (?, ?, ?, ?, ?)',
      ['login', email, userType, true, 'Login successful']
    );

    res.json({ success: true, message: 'Login successful', token, user: userData });
  } catch (error) {
    console.error('Login error:', error.message, error.stack);
    await db.execute(
      'INSERT INTO audit_logs (event_type, user_email, user_type, success, message) VALUES (?, ?, ?, ?, ?)',
      ['login', req.body.email || 'unknown', 'user', false, 'Internal server error']
    );
    res.status(500).json({ success: false, message: 'Login failed. Please try again.' });
  }
});

// === Protected Route Example ===
app.get('/api/dashboard', authenticateToken, (req, res) => {
  // Access req.user which contains { id, email, userType }
  res.json({
    success: true,
    message: `Welcome to your dashboard, ${req.user.email}`,
    user: req.user,
  });
});

// Audit logs endpoint
app.get('/api/audit/logs', async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM audit_logs ORDER BY timestamp DESC');
    res.json({ logs: rows });
  } catch (err) {
    console.error('Error fetching audit logs:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});






// === GET: All Pending Users ===
app.get("/api/admin/pending-users", async (req, res) => {
  try {
    let keys = [];
    try {
      const listResponse = await vault.list("kv/metadata/pending-users");
      keys = listResponse.data.keys;
    } catch (err) {
      if (err.response?.statusCode === 404) {
        // No users exist yet
        return res.json({ success: true, users: [] });
      } else {
        throw err; // Other errors
      }
    }

    const users = await Promise.all(
      keys.map(async (email) => {
        const secret = await vault.read(`kv/data/pending-users/${email}`);
        const { approved, token } = secret.data.data;
        return { email, approved, token };
      })
    );

    const pending = users.filter((user) => user.approved === false);
    res.json({ success: true, users: pending });
  } catch (err) {
    console.error("Vault list error:", err?.response?.data || err);
    res.status(500).json({ success: false, message: "Failed to fetch users" });
  }
});

// === POST: Approve User ===
// === POST: Approve User ===
app.post("/api/admin/approve-user", async (req, res) => {
  const { email, organizationEmail } = req.body;

  if (!email || !organizationEmail) {
    return res.status(400).json({
      success: false,
      message: "Both user email and organizationEmail are required",
    });
  }

  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();

    // 1. Read Vault data
    const pendingData = await vault.read(`kv/data/pending-users/${email}`);
    const { token } = pendingData.data.data;

    // 2. Write to approved-users path
    await vault.write(`kv/data/approved-users/${email}`, {
      data: {
        approved: true,
        token,
      },
    });

    // 3. Delete from pending path
    await vault.delete(`kv/metadata/pending-users/${email}`);

    // 4. Update DB status to "approved"
    await connection.execute(
      `UPDATE users SET status = 'approved' WHERE email = ?`,
      [email]
    );

    // ✅ 5. Log approval using organization (NOT "admin")
    await logAudit(
      connection,
      "approve_user",
      organizationEmail, // <- the org user who approved
      "organization",
      true,
      `User (${email}) approved by organization (${organizationEmail})`
    );

    await connection.commit();

    res.json({ success: true, message: "User approved and status updated" });
  } catch (error) {
    await connection.rollback();

    const errMsg = error?.response?.data || error.message || error;

    await logAudit(
      connection,
      "approve_user",
      organizationEmail || "unknown",
      "organization",
      false,
      `User (${email}) approval failed: ${errMsg}`
    ).catch(console.error);

    console.error("Approval error:", errMsg);
    res.status(500).json({ success: false, message: "Failed to approve user" });
  } finally {
    connection.release();
  }
});


// === GET: All Approved Users ===
app.get("/api/admin/approved-users", async (req, res) => {
  try {
    let keys = [];
    try {
      const listResponse = await vault.list("kv/metadata/approved-users");
      keys = listResponse.data.keys;
    } catch (err) {
      if (err.response?.statusCode === 404) {
        return res.json({ success: true, users: [] }); // Return empty
      } else {
        throw err;
      }
    }

    const users = await Promise.all(
      keys.map(async (email) => {
        const secret = await vault.read(`kv/data/approved-users/${email}`);
        const { token } = secret.data.data;
        return { email, token };
      })
    );

    res.json({ success: true, users });
  } catch (err) {
    console.error("Vault list error:", err?.response?.data || err);
    res.status(500).json({ success: false, message: "Failed to fetch approved users" });
  }
});


// === DELETE: Users ===
app.delete("/api/admin/delete-user", async (req, res) => {
  const { email, type } = req.body; // type = 'pending' | 'approved'

  if (!email || !type) {
    return res.status(400).json({ success: false, message: "Email and type are required" });
  }

  const vaultPath = `kv/metadata/${type}-users/${email}`;
  const connection = await db.getConnection();

  try {
    await connection.beginTransaction();

    // Delete from Vault
    await vault.delete(vaultPath);

    // Delete from MySQL
    await connection.execute(`DELETE FROM users WHERE email = ?`, [email]);

    await connection.commit();
    res.json({ success: true, message: `Deleted ${email} from ${type}` });
  } catch (err) {
    await connection.rollback();
    console.error("Delete user error:", err?.response?.data || err);
    res.status(500).json({ success: false, message: "Failed to delete user" });
  } finally {
    connection.release();
  }
});




// Admin approval endpoint
app.get('/api/admin/approve/:token', async (req, res) => {
  const connection = await db.getConnection();
  
  try {
    await connection.beginTransaction();
    
    const { token } = req.params;

    if (!token) {
      return res.status(400).json({
        success: false,
        message: 'Approval token is required'
      });
    }

    // Find user by approval token
    const [users] = await connection.execute(
      'SELECT * FROM users WHERE approval_token = ? AND status = ?',
      [token, 'pending']
    );

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Invalid or expired approval token'
      });
    }

    const user = users[0];

    // Generate auth key
    const authKey = generateAuthKey();

    // Update user status and auth key
    await connection.execute(
      'UPDATE users SET status = ?, auth_key = ?, approval_token = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      ['approved', authKey, user.id]
    );

    await connection.commit();

    // Send approval notification to user (async)
    const userData = {
      email: user.email,
      first_name: user.first_name,
      auth_key: authKey
    };
    
    sendUserApprovalNotification(userData).catch(console.error);

    res.json({
      success: true,
      message: 'User approved successfully! Notification email sent.',
      user: {
        id: user.id,
        email: user.email,
        name: `${user.first_name} ${user.last_name}`,
        approved_at: new Date().toISOString()
      }
    });

  } catch (error) {
    await connection.rollback();
    console.error('Approval error:', error);
    res.status(500).json({
      success: false,
      message: 'Approval failed. Please try again.'
    });
  } finally {
    connection.release();
  }
});

// Get pending users (for admin dashboard)
app.get('/api/admin/pending-users', async (req, res) => {
  try {
    const [users] = await db.execute(`
      SELECT id, email, first_name, last_name, phone, organization, created_at 
      FROM users 
      WHERE status = ? 
      ORDER BY created_at DESC
    `, ['pending']);

    res.json({
      success: true,
      count: users.length,
      users
    });
  } catch (error) {
    console.error('Get pending users error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch pending users'
    });
  }
});

// Get user profile (protected route)
app.get('/api/user/profile', verifyToken, async (req, res) => {
  try {
    const [users] = await db.execute(
      'SELECT id, email, first_name, last_name, phone, organization, auth_key, status, created_at FROM users WHERE id = ?',
      [req.user.userId]
    );

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      user: users[0]
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch profile'
    });
  }
});

// Get all users (admin only - optional)
app.get('/api/admin/users', async (req, res) => {
  try {
    const [users] = await db.execute(`
      SELECT id, email, first_name, last_name, phone, organization, status, created_at, updated_at 
      FROM users 
      ORDER BY created_at DESC
    `);

    res.json({
      success: true,
      count: users.length,
      users
    });
  } catch (error) {
    console.error('Get all users error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch users'
    });
  }
});

// Create new organization

app.use(express.json());


app.post('/api/organizations', async (req, res) => {
  const {
    first_name,
    last_name,
    email,
    organization_domain,
    phone,
    password,
  } = req.body;

  if (!first_name || !last_name || !email || !organization_domain || !password) {
    return res.status(400).json({
      success: false,
      message: 'First name, last name, email, organization domain, and password are required',
    });
  }

  try {
    const [existing] = await db.execute(
      'SELECT id FROM organizations WHERE organization_domain = ?',
      [organization_domain]
    );

    if (existing.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Organization domain already exists',
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const [result] = await db.execute(
      `INSERT INTO organizations 
        (first_name, last_name, email, organization_domain, phone, password) 
       VALUES (?, ?, ?, ?, ?, ?)`,
      [first_name, last_name, email, organization_domain, phone, hashedPassword]
    );

    res.status(201).json({
      success: true,
      message: 'Organization registered successfully',
      organizationId: result.insertId,
    });
  } catch (error) {
    console.error('Error creating organization:', error.message);
    res.status(500).json({
      success: false,
      message: 'Failed to register organization',
    });
  }
});


// === Send OTP ===
app.post('/api/auth/request-reset', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    await logAudit(db, 'send_otp', 'unknown', 'organization', false, 'Email required');
    return res.status(400).json({ message: 'Email required' });
  }

  try {
    const [rows] = await db.execute('SELECT * FROM organizations WHERE email = ?', [email]);
    if (rows.length === 0) {
      await logAudit(db, 'send_otp', email, 'organization', false, 'Email not found');
      return res.status(404).json({ message: 'Email not found' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = new Date(Date.now() + 15 * 60 * 1000);

    await db.execute(
      'UPDATE organizations SET reset_otp = ?, reset_otp_expires = ? WHERE email = ?',
      [otp, expires, email]
    );

    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: Number(process.env.EMAIL_PORT),
      secure: false,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    await transporter.sendMail({
      from: `"Support" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Your Password Reset OTP',
      text: `Your OTP is ${otp}. It expires in 15 minutes.`,
    });

    await logAudit(db, 'send_otp', email, 'organization', true, 'OTP sent via email');
    res.json({ message: 'OTP sent to your email' });
  } catch (error) {
    console.error('Error sending OTP:', error);
    await logAudit(db, 'send_otp', email || 'unknown', 'organization', false, 'Internal error sending OTP');
    res.status(500).json({ message: 'Failed to send OTP' });
  }
});

// === Confirm OTP and Reset Password ===
app.post('/api/auth/confirm-reset', async (req, res) => {
  const { email, otp, newPassword, confirmPassword } = req.body;

  if (!email || !otp || !newPassword || !confirmPassword) {
    await logAudit(db, 'verify_otp', email || 'unknown', 'organization', false, 'Missing fields');
    return res.status(400).json({ message: 'All fields are required' });
  }

  if (newPassword !== confirmPassword) {
    await logAudit(db, 'verify_otp', email, 'organization', false, 'Passwords do not match');
    return res.status(400).json({ message: 'Passwords do not match' });
  }

  try {
    const [rows] = await db.execute(
      'SELECT * FROM organizations WHERE email = ? AND reset_otp = ? AND reset_otp_expires > NOW()',
      [email, otp]
    );

    if (rows.length === 0) {
      await logAudit(db, 'verify_otp', email, 'organization', false, 'Invalid or expired OTP');
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await db.execute(
      'UPDATE organizations SET password = ?, reset_otp = NULL, reset_otp_expires = NULL WHERE email = ?',
      [hashedPassword, email]
    );

    await logAudit(db, 'verify_otp', email, 'organization', true, 'Password reset successful');
    res.json({ message: 'Password reset successful' });
  } catch (error) {
    console.error(error);
    await logAudit(db, 'verify_otp', email || 'unknown', 'organization', false, 'Error resetting password');
    res.status(500).json({ message: 'Error resetting password' });
  }
});

// === Reset via Token (optional flow) ===
app.post('/api/auth/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    await logAudit(db, 'reset_password', 'unknown', 'organization', false, 'Invalid request');
    return res.status(400).json({ message: 'Invalid request' });
  }

  try {
    const [rows] = await db.execute(
      'SELECT * FROM organizations WHERE reset_token = ? AND reset_token_expires > NOW()',
      [token]
    );

    if (rows.length === 0) {
      await logAudit(db, 'reset_password', 'unknown', 'organization', false, 'Invalid or expired token');
      return res.status(400).json({ message: 'Invalid or expired token' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await db.execute(
      'UPDATE organizations SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?',
      [hashedPassword, rows[0].id]
    );

    await logAudit(db, 'reset_password', rows[0].email, 'organization', true, 'Password reset via token successful');
    res.json({ message: 'Password reset successful' });
  } catch (err) {
    console.error(err);
    await logAudit(db, 'reset_password', 'unknown', 'organization', false, 'Error resetting password');
    res.status(500).json({ message: 'Error resetting password' });
  }
});


// Constants

// const MAX_ATTEMPTS = 3;
// const BLOCK_DURATION_MINUTES = 15;

// router.post('/api/auth/login', async (req, res) => {
//   const { email, password } = req.body;

//   if (!email || !password) {
//     return res.status(400).json({ message: 'Email and password are required' });
//   }

//   try {
//     const [rows] = await db.execute('SELECT * FROM organizations WHERE email = ?', [email]);

//     if (rows.length === 0) {
//       return res.status(404).json({ message: 'Account not found' });
//     }

//     const user = rows[0];

//     // Calculate block window
//     const now = new Date();
//     const blockWindowStart = new Date(now.getTime() - BLOCK_DURATION_MINUTES * 60 * 1000);
//     const lastFailed = user.last_failed_at ? new Date(user.last_failed_at) : null;

//     if (
//       user.failed_attempts >= MAX_ATTEMPTS &&
//       lastFailed &&
//       lastFailed >= blockWindowStart
//     ) {
//       const remainingMinutes = Math.ceil((lastFailed.getTime() + BLOCK_DURATION_MINUTES * 60 * 1000 - now.getTime()) / 60000);
//       return res.status(403).json({
//         message: `Account locked. Try again in ${remainingMinutes} minute(s).`,
//       });
//     }

//     const passwordMatch = await bcrypt.compare(password, user.password);

//     if (!passwordMatch) {
//       await db.execute(
//         'UPDATE organizations SET failed_attempts = failed_attempts + 1, last_failed_at = CURRENT_TIMESTAMP WHERE id = ?',
//         [user.id]
//       );

//       return res.status(401).json({ message: 'Invalid email or password' });
//     }

//     // SUCCESS: Reset login attempts
//     await db.execute(
//       'UPDATE organizations SET failed_attempts = 0, last_failed_at = NULL WHERE id = ?',
//       [user.id]
//     );

//     const token = jwt.sign(
//       { id: user.id, email: user.email },
//       process.env.JWT_SECRET,
//       { expiresIn: '1d' }
//     );

//     res.status(200).json({
//       success: true,
//       token,
//       user: {
//         id: user.id,
//         email: user.email,
//         first_name: user.first_name,
//         last_name: user.last_name,
//         organization_domain: user.organization_domain,
//       },
//     });
//   } catch (err) {
//     console.error('Login error:', err.message);
//     res.status(500).json({ message: 'Server error' });
//   }
// });



















// Backend API endpoint to get all organization domains
app.get('/api/organizations/domains', async (req, res) => {
  try {
    // Fetch all organization domains from MySQL
    const [rows] = await db.execute(`
      SELECT 
        id, 
        organization_domain,
        first_name,
        last_name,
        email,
        created_at
      FROM organizations 
      WHERE organization_domain IS NOT NULL 
      AND organization_domain != ''
      ORDER BY organization_domain ASC
    `);

    // Return the organization domains
    res.json({
      success: true,
      data: rows,
      message: 'Organization domains fetched successfully'
    });

  } catch (error) {
    console.error('Error fetching organization domains:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch organization domains',
      error: error.message
    });
  }
});

// Alternative endpoint to get unique domains only (if you want just the domain names)
app.get('/api/organizations/unique-domains', async (req, res) => {
  try {
    // Fetch unique organization domains from MySQL
    const [rows] = await db.execute(`
      SELECT DISTINCT organization_domain
      FROM organizations 
      WHERE organization_domain IS NOT NULL 
      AND organization_domain != ''
      ORDER BY organization_domain ASC
    `);

    // Return just the domain names
    const domains = rows.map(row => row.organization_domain);

    res.json({
      success: true,
      data: domains,
      message: 'Unique organization domains fetched successfully'
    });

  } catch (error) {
    console.error('Error fetching unique organization domains:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch organization domains',
      error: error.message
    });
  }
});





















// Reject user (admin functionality)
app.post('/api/admin/reject/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    
    const [result] = await db.execute(
      'UPDATE users SET status = ?, approval_token = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status = ?',
      ['rejected', userId, 'pending']
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found or already processed'
      });
    }

    res.json({
      success: true,
      message: 'User rejected successfully'
    });
  } catch (error) {
    console.error('Reject user error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to reject user'
    });
  }
});

// Logout (optional - mainly for client-side token cleanup)
app.post('/api/auth/logout', verifyToken, (req, res) => {
  res.json({
    success: true,
    message: 'Logged out successfully'
  });
});

// Error handling middleware
app.use(errorHandler);

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'API endpoint not found',
    path: req.originalUrl
  });
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  if (db) {
    await db.end();
  }
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, shutting down gracefully');
  if (db) {
    await db.end();
  }
  process.exit(0);
});

// Start server
async function startServer() {
  try {
    await initializeDatabase();
    
    app.listen(PORT, () => {
      console.log('🚀 Server is running on port', PORT);
      console.log('📧 Email configured:', !!process.env.EMAIL_USER);
      console.log('🔑 JWT Secret configured:', !!process.env.JWT_SECRET);
      console.log('🌐 Environment:', process.env.NODE_ENV || 'development');
      console.log('📍 Frontend URL:', process.env.FRONTEND_URL || 'http://localhost:3000');
      console.log('\n📋 Available endpoints:');
      console.log('   POST /api/auth/register - User registration');
      console.log('   POST /api/auth/login - User login');
      console.log('   GET  /api/admin/approve/:token - Admin approval');
      console.log('   GET  /api/user/profile - Get user profile (protected)');
      console.log('   GET  /api/admin/pending-users - Get pending users');
      console.log('   GET  /api/health - Health check');
    });
    
  } catch (error) {
    console.error('❌ Failed to start server:', error.message);
    process.exit(1);
  }
}

// Initialize and start the server
startServer();

module.exports = app;