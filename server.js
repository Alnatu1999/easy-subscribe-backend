// server.js - CommonJS version
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const dotenv = require('dotenv');
const axios = require('axios');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const { connectDB, User, Transaction, AdminRole, Notification, Commission } = require('./db.js');
dotenv.config();
const app = express();
app.use(helmet());

// Enhanced CORS configuration - FIXED
const allowedOrigins = [
  'http://localhost:5173',
  'http://localhost:5500',
  'http://127.0.0.1:5500'
];

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log('Origin not allowed by CORS:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '1mb' }));

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: 'Too many authentication attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/auth/', authLimiter);

// Connect to Database
connectDB();

// Constants
const PORT = process.env.PORT || 5001;
const APP_BASE_URL = process.env.APP_BASE_URL || 'http://localhost:5173';
const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET_KEY;
const PAYSTACK_INIT_URL = 'https://api.paystack.co/transaction/initialize';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'your-refresh-secret';

// Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return response(res, false, null, 'Access token required', 401);
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return response(res, false, null, 'Invalid token', 403);
    req.user = user;
    next();
  });
};

const authorizeRole = (roles) => {
  return (req, res, next) => {
    if (!req.user) return response(res, false, null, 'Unauthorized', 401);
    
    if (!roles.includes(req.user.role)) {
      return response(res, false, null, 'Insufficient permissions', 403);
    }
    
    next();
  };
};

// Helper Functions
function response(res, success, data = null, message = '', code = 200) {
  return res.status(code).json({
    success,
    data,
    message,
    timestamp: new Date().toISOString()
  });
}

function required(obj, keys) { 
  for (const k of keys) if (!obj[k]) return k; 
  return null; 
}

// Generate Reference
function generateReference(prefix = 'TXN') {
  return `${prefix}-${Date.now()}-${Math.floor(Math.random() * 1000000)}`;
}

// Validate email format
function isValidEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(String(email).toLowerCase());
}

// Validate phone number format (Nigerian format)
function isValidPhone(phone) {
  const re = /^(0|234)(7|8|9)[01]\d{8}$/;
  return re.test(String(phone));
}

// Send Email
const sendEmail = async (to, subject, html) => {
  try {
    const transporter = nodemailer.createTransporter({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });
    
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to,
      subject,
      html
    };
    
    await transporter.sendMail(mailOptions);
  } catch (err) {
    console.error('EMAIL_SEND_ERR', err);
    // Don't fail the whole process if email fails
  }
};

// Generate JWT tokens
function generateTokens(user) {
  const accessToken = jwt.sign(
    { id: user._id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: '15m' }
  );
  
  const refreshToken = jwt.sign(
    { id: user._id },
    JWT_REFRESH_SECRET,
    { expiresIn: '7d' }
  );
  
  return { accessToken, refreshToken };
}

// Bill Fulfilment Function (for webhooks)
async function fulfilBill({ amount, email, serviceType, billersCode, serviceID, variation_code, phone, paystack_reference }) {
  try {
    const naira = Math.round(Number(amount || 0) / 100);
    
    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return { success: false, error: 'User not found' };
    }
    
    // Create transaction record
    const reference = generateReference();
    const transaction = new Transaction({
      userId: user._id,
      type: serviceType,
      amount: naira,
      reference,
      status: 'pending',
      metadata: {
        billersCode,
        serviceID,
        variation_code,
        phone,
        paystack_reference
      }
    });
    
    await transaction.save();
    
    // Process based on service type
    let result;
    switch (serviceType) {
      case 'airtime':
        result = await processAirtimePurchase(serviceID, phone, naira, reference);
        break;
      case 'data':
        result = await processDataPurchase(serviceID, phone, variation_code, reference);
        break;
      case 'electricity':
        result = await processElectricityPayment(serviceID, billersCode, variation_code, naira, reference);
        break;
      case 'tv':
        result = await processTVSubscription(serviceID, billersCode, variation_code, reference);
        break;
      case 'wallet-funding':
        // Update wallet balance
        user.walletBalance += naira;
        await user.save();
        result = { success: true };
        break;
      default:
        result = { success: false, error: 'Unknown service type' };
    }
    
    // Update transaction status
    transaction.status = result.success ? 'successful' : 'failed';
    if (result.token) {
      transaction.metadata.token = result.token;
    }
    await transaction.save();
    
    // Send notification
    const notification = new Notification({
      userId: user._id,
      title: `${serviceType} ${result.success ? 'Successful' : 'Failed'}`,
      message: result.success 
        ? `Your ${serviceType} transaction of ₦${naira} was successful. Reference: ${reference}`
        : `Your ${serviceType} transaction failed. Please contact support.`
    });
    await notification.save();
    
    return { success: result.success };
  } catch (err) {
    console.error('FULFIL_BILL_ERR', err);
    return { success: false, error: err.message };
  }
}

// Webhook for Paystack
app.post('/webhooks/paystack', express.raw({ type: '*/*' }), async (req, res) => {
  try {
    const signature = req.headers['x-paystack-signature'];
    const hash = crypto.createHmac('sha512', PAYSTACK_SECRET).update(req.body).digest('hex');
    
    if (hash !== signature) {
      console.error('Invalid webhook signature');
      return response(res, false, null, 'Invalid signature', 401);
    }
    
    const event = JSON.parse(req.body.toString());
    
    if (event?.event !== 'charge.success') {
      return response(res, true, null, 'Ignored event', 200);
    }
    
    const data = event?.data;
    const amount = data?.amount; // kobo
    const email = data?.customer?.email;
    const meta = data?.metadata || {};
    
    const fulfil = await fulfilBill({
      amount,
      email,
      serviceType: meta.serviceType,
      billersCode: meta.billersCode,
      serviceID: meta.serviceID,
      variation_code: meta.variation_code,
      phone: meta.phone,
      paystack_reference: data?.reference,
    });
    
    if (!fulfil?.success) {
      console.error('FULFILMENT_FAILED', fulfil);
      // You can alert admin or queue a retry here
    }
    
    return response(res, true, null, 'OK', 200);
  } catch (err) {
    console.error('WEBHOOK_ERR', err?.message);
    return response(res, false, null, 'Webhook processing failed', 500);
  }
});

// Authentication Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    
    // Validate input
    const missingField = required({ name, email, password }, ['name', 'email', 'password']);
    if (missingField) {
      return response(res, false, null, `Missing required field: ${missingField}`, 400);
    }
    
    if (!isValidEmail(email)) {
      return response(res, false, null, 'Invalid email format', 400);
    }
    
    if (phone && !isValidPhone(phone)) {
      return response(res, false, null, 'Invalid phone number format', 400);
    }
    
    if (password.length < 8) {
      return response(res, false, null, 'Password must be at least 8 characters', 400);
    }
    
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return response(res, false, null, 'User already exists', 409);
    }
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Create user
    const user = new User({
      name,
      email,
      password: hashedPassword,
      phone,
      isActive: true,  // Ensure user is active by default
      role: 'user'      // Ensure role is set
    });
    
    await user.save();
    
    // Generate JWT tokens
    const { accessToken, refreshToken } = generateTokens(user);
    
    // Send welcome email (non-blocking)
    sendEmail(
      email,
      'Welcome to EasySubscribe',
      `<h1>Welcome to EasySubscribe</h1>
      <p>Thank you for registering with us. You can now enjoy seamless bill payments.</p>`
    ).catch(err => console.error('WELCOME_EMAIL_ERR', err));
    
    response(res, true, {
      accessToken,
      refreshToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        walletBalance: user.walletBalance
      }
    }, 'User registered successfully');
  } catch (err) {
    console.error('REGISTER_ERR', err);
    response(res, false, null, 'Registration failed', 500);
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return response(res, false, null, 'Missing email or password', 400);
    }
    
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return response(res, false, null, 'Invalid credentials', 401);
    }
    
    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return response(res, false, null, 'Invalid credentials', 401);
    }
    
    // Check if user is active
    if (!user.isActive) {
      return response(res, false, null, 'Account is deactivated', 403);
    }
    
    // Generate JWT tokens
    const { accessToken, refreshToken } = generateTokens(user);
    
    response(res, true, {
      accessToken,
      refreshToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        walletBalance: user.walletBalance
      }
    }, 'Login successful');
  } catch (err) {
    console.error('LOGIN_ERR', err);
    response(res, false, null, 'Login failed', 500);
  }
});

app.post('/api/auth/refresh-token', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return response(res, false, null, 'Refresh token required', 401);
    }
    
    jwt.verify(refreshToken, JWT_REFRESH_SECRET, async (err, user) => {
      if (err) return response(res, false, null, 'Invalid refresh token', 403);
      
      const dbUser = await User.findById(user.id);
      if (!dbUser || !dbUser.isActive) {
        return response(res, false, null, 'User not found or inactive', 404);
      }
      
      const { accessToken } = generateTokens(dbUser);
      
      response(res, true, { accessToken }, 'Token refreshed successfully');
    });
  } catch (err) {
    console.error('REFRESH_TOKEN_ERR', err);
    response(res, false, null, 'Failed to refresh token', 500);
  }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return response(res, false, null, 'Email is required', 400);
    }
    
    if (!isValidEmail(email)) {
      return response(res, false, null, 'Invalid email format', 400);
    }
    
    const user = await User.findOne({ email });
    if (!user) {
      // Don't reveal that the user doesn't exist
      return response(res, true, null, 'If your email is registered, you will receive a password reset link');
    }
    
    // Generate reset token
    const resetToken = crypto.randomBytes(20).toString('hex');
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();
    
    // Send reset email (non-blocking)
    const resetUrl = `${APP_BASE_URL}/reset-password.html?token=${resetToken}`;
    
    sendEmail(
      email,
      'Password Reset Request',
      `<h1>Password Reset Request</h1>
      <p>You requested a password reset for your EasySubscribe account.</p>
      <p>Click the link below to reset your password:</p>
      <a href="${resetUrl}">Reset Password</a>
      <p>This link is valid for 1 hour.</p>
      <p>If you didn't request this, please ignore this email.</p>`
    ).catch(err => console.error('RESET_EMAIL_ERR', err));
    
    response(res, true, null, 'If your email is registered, you will receive a password reset link');
  } catch (err) {
    console.error('FORGOT_PASSWORD_ERR', err);
    response(res, false, null, 'Failed to process password reset request', 500);
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, password } = req.body;
    
    if (!token || !password) {
      return response(res, false, null, 'Token and password are required', 400);
    }
    
    if (password.length < 8) {
      return response(res, false, null, 'Password must be at least 8 characters', 400);
    }
    
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }
    });
    
    if (!user) {
      return response(res, false, null, 'Invalid or expired reset token', 400);
    }
    
    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Update user
    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();
    
    // Send confirmation email (non-blocking)
    sendEmail(
      user.email,
      'Password Reset Successful',
      `<h1>Password Reset Successful</h1>
      <p>Your password has been successfully reset.</p>
      <p>If you didn't initiate this request, please contact support immediately.</p>`
    ).catch(err => console.error('RESET_CONFIRM_EMAIL_ERR', err));
    
    response(res, true, null, 'Password reset successful');
  } catch (err) {
    console.error('RESET_PASSWORD_ERR', err);
    response(res, false, null, 'Failed to reset password', 500);
  }
});

// User Routes
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return response(res, false, null, 'User not found', 404);
    }
    
    response(res, true, { user }, 'User profile retrieved');
  } catch (err) {
    console.error('GET_PROFILE_ERR', err);
    response(res, false, null, 'Failed to get user profile', 500);
  }
});

app.put('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const { name, phone } = req.body;
    
    const user = await User.findById(req.user.id);
    if (!user) {
      return response(res, false, null, 'User not found', 404);
    }
    
    // Update user fields
    if (name) user.name = name;
    if (phone) {
      if (!isValidPhone(phone)) {
        return response(res, false, null, 'Invalid phone number format', 400);
      }
      user.phone = phone;
    }
    
    await user.save();
    
    response(res, true, { 
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        role: user.role,
        walletBalance: user.walletBalance
      }
    }, 'Profile updated successfully');
  } catch (err) {
    console.error('UPDATE_PROFILE_ERR', err);
    response(res, false, null, 'Failed to update profile', 500);
  }
});

app.post('/api/user/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
      return response(res, false, null, 'Current password and new password are required', 400);
    }
    
    if (newPassword.length < 8) {
      return response(res, false, null, 'New password must be at least 8 characters', 400);
    }
    
    const user = await User.findById(req.user.id);
    if (!user) {
      return response(res, false, null, 'User not found', 404);
    }
    
    // Verify current password
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return response(res, false, null, 'Current password is incorrect', 401);
    }
    
    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    
    // Update password
    user.password = hashedPassword;
    await user.save();
    
    // Send confirmation email (non-blocking)
    sendEmail(
      user.email,
      'Password Changed Successfully',
      `<h1>Password Changed</h1>
      <p>Your password has been successfully changed.</p>
      <p>If you didn't initiate this request, please contact support immediately.</p>`
    ).catch(err => console.error('PASSWORD_CHANGE_EMAIL_ERR', err));
    
    response(res, true, null, 'Password changed successfully');
  } catch (err) {
    console.error('CHANGE_PASSWORD_ERR', err);
    response(res, false, null, 'Failed to change password', 500);
  }
});

// Notification Routes
app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 10, unreadOnly = false } = req.query;
    const skip = (page - 1) * limit;
    
    const filter = { userId: req.user.id };
    if (unreadOnly === 'true') filter.isRead = false;
    
    const notifications = await Notification.find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Notification.countDocuments(filter);
    const unreadCount = await Notification.countDocuments({ userId: req.user.id, isRead: false });
    
    response(res, true, {
      notifications,
      unreadCount,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / limit)
      }
    }, 'Notifications retrieved');
  } catch (err) {
    console.error('GET_NOTIFICATIONS_ERR', err);
    response(res, false, null, 'Failed to get notifications', 500);
  }
});

app.put('/api/notifications/:id/read', authenticateToken, async (req, res) => {
  try {
    const notification = await Notification.findOne({
      _id: req.params.id,
      userId: req.user.id
    });
    
    if (!notification) {
      return response(res, false, null, 'Notification not found', 404);
    }
    
    notification.isRead = true;
    await notification.save();
    
    response(res, true, null, 'Notification marked as read');
  } catch (err) {
    console.error('MARK_NOTIFICATION_READ_ERR', err);
    response(res, false, null, 'Failed to mark notification as read', 500);
  }
});

app.put('/api/notifications/read-all', authenticateToken, async (req, res) => {
  try {
    await Notification.updateMany(
      { userId: req.user.id, isRead: false },
      { isRead: true }
    );
    
    response(res, true, null, 'All notifications marked as read');
  } catch (err) {
    console.error('MARK_ALL_NOTIFICATIONS_READ_ERR', err);
    response(res, false, null, 'Failed to mark notifications as read', 500);
  }
});

// Wallet Routes
app.post('/api/wallet/fund', authenticateToken, async (req, res) => {
  try {
    const { amount, paymentMethod } = req.body;
    
    if (!amount || amount < 100) {
      return response(res, false, null, 'Invalid amount (minimum ₦100)', 400);
    }
    
    const user = await User.findById(req.user.id);
    if (!user) {
      return response(res, false, null, 'User not found', 404);
    }
    
    const reference = generateReference('WALLET');
    
    // Initialize payment with Paystack
    const initRes = await axios.post(PAYSTACK_INIT_URL, {
      amount: amount * 100, // Convert to kobo
      email: user.email,
      metadata: {
        userId: user._id,
        serviceType: 'wallet-funding',
        reference
      },
      callback_url: `${APP_BASE_URL}/payment-success.html`
    }, {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET}` }
    });
    
    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: 'wallet-funding',
      amount,
      reference,
      status: 'pending',
      metadata: { paymentMethod }
    });
    
    await transaction.save();
    
    response(res, true, {
      authorization_url: initRes?.data?.data?.authorization_url,
      reference
    }, 'Wallet funding initiated');
  } catch (err) {
    console.error('WALLET_FUND_ERR', err?.response?.data || err.message);
    response(res, false, null, 'Failed to initialize wallet funding', 500);
  }
});

app.post('/api/wallet/transfer', authenticateToken, async (req, res) => {
  try {
    const { recipientEmail, amount } = req.body;
    
    if (!recipientEmail || !amount || amount < 100) {
      return response(res, false, null, 'Invalid transfer parameters', 400);
    }
    
    if (!isValidEmail(recipientEmail)) {
      return response(res, false, null, 'Invalid recipient email format', 400);
    }
    
    const sender = await User.findById(req.user.id);
    if (!sender || sender.walletBalance < amount) {
      return response(res, false, null, 'Insufficient balance', 400);
    }
    
    const recipient = await User.findOne({ email: recipientEmail });
    if (!recipient) {
      return response(res, false, null, 'Recipient not found', 404);
    }
    
    if (sender._id.toString() === recipient._id.toString()) {
      return response(res, false, null, 'Cannot transfer to yourself', 400);
    }
    
    // Create transaction record
    const reference = generateReference('TRANSFER');
    const transaction = new Transaction({
      userId: sender._id,
      type: 'transfer',
      amount,
      reference,
      status: 'pending',
      metadata: { recipientId: recipient._id, recipientEmail }
    });
    
    await transaction.save();
    
    // Process transfer
    sender.walletBalance -= amount;
    recipient.walletBalance += amount;
    
    await Promise.all([sender.save(), recipient.save()]);
    
    // Update transaction status
    transaction.status = 'successful';
    await transaction.save();
    
    // Create notifications
    await Promise.all([
      new Notification({
        userId: sender._id,
        title: 'Transfer Successful',
        message: `You transferred ₦${amount} to ${recipientEmail}`
      }).save(),
      new Notification({
        userId: recipient._id,
        title: 'Wallet Credited',
        message: `You received ₦${amount} from ${sender.email}`
      }).save()
    ]);
    
    response(res, true, { 
      reference,
      newBalance: sender.walletBalance
    }, 'Transfer successful');
  } catch (err) {
    console.error('TRANSFER_ERR', err);
    response(res, false, null, 'Transfer failed', 500);
  }
});

app.get('/api/wallet/balance', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return response(res, false, null, 'User not found', 404);
    }
    
    response(res, true, { balance: user.walletBalance }, 'Wallet balance retrieved');
  } catch (err) {
    console.error('WALLET_BALANCE_ERR', err);
    response(res, false, null, 'Failed to get wallet balance', 500);
  }
});

app.get('/api/wallet/transactions', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 10, type } = req.query;
    const skip = (page - 1) * limit;
    
    const filter = { userId: req.user.id };
    if (type) filter.type = type;
    
    const transactions = await Transaction.find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Transaction.countDocuments(filter);
    
    response(res, true, {
      transactions,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / limit)
      }
    }, 'Wallet transactions retrieved');
  } catch (err) {
    console.error('WALLET_TRANSACTIONS_ERR', err);
    response(res, false, null, 'Failed to get wallet transactions', 500);
  }
});

// Service Routes
app.post('/api/services/airtime', authenticateToken, async (req, res) => {
  try {
    const { network, phone, amount, paymentMethod } = req.body;
    
    if (!network || !phone || !amount || amount < 50) {
      return response(res, false, null, 'Invalid request parameters', 400);
    }
    
    if (!isValidPhone(phone)) {
      return response(res, false, null, 'Invalid phone number format', 400);
    }
    
    const user = await User.findById(req.user.id);
    if (!user) {
      return response(res, false, null, 'User not found', 404);
    }
    
    // Check wallet balance if paying with wallet
    if (paymentMethod === 'wallet' && user.walletBalance < amount) {
      return response(res, false, null, 'Insufficient wallet balance', 400);
    }
    
    const reference = generateReference('AIRTIME');
    
    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: 'airtime',
      amount,
      reference,
      status: 'pending',
      metadata: { network, phone, paymentMethod }
    });
    
    await transaction.save();
    
    // Process payment
    if (paymentMethod === 'wallet') {
      // Deduct from wallet
      user.walletBalance -= amount;
      await user.save();
      
      // Process airtime purchase
      const result = await processAirtimePurchase(network, phone, amount, reference);
      
      // Update transaction status
      transaction.status = result.success ? 'successful' : 'failed';
      await transaction.save();
      
      if (result.success) {
        // Create notification
        await new Notification({
          userId: user._id,
          title: 'Airtime Purchase Successful',
          message: `You purchased ₦${amount} airtime for ${phone}`
        }).save();
        
        response(res, true, { reference }, 'Airtime purchase successful');
      } else {
        // Refund wallet if failed
        user.walletBalance += amount;
        await user.save();
        
        // Create notification
        await new Notification({
          userId: user._id,
          title: 'Airtime Purchase Failed',
          message: `Your airtime purchase for ${phone} failed. Amount refunded.`
        }).save();
        
        response(res, false, null, result.message || 'Airtime purchase failed', 400);
      }
    } else {
      // Initialize payment with Paystack
      const initRes = await axios.post(PAYSTACK_INIT_URL, {
        amount: amount * 100, // Convert to kobo
        email: user.email,
        metadata: {
          userId: user._id,
          serviceType: 'airtime',
          reference,
          network,
          phone
        },
        callback_url: `${APP_BASE_URL}/payment-success.html`
      }, {
        headers: { Authorization: `Bearer ${PAYSTACK_SECRET}` }
      });
      
      response(res, true, {
        authorization_url: initRes?.data?.data?.authorization_url,
        reference
      }, 'Airtime purchase initiated');
    }
  } catch (err) {
    console.error('AIRTIME_ERR', err);
    response(res, false, null, 'Airtime purchase failed', 500);
  }
});

app.post('/api/services/data', authenticateToken, async (req, res) => {
  try {
    const { network, phone, plan, paymentMethod } = req.body;
    
    if (!network || !phone || !plan) {
      return response(res, false, null, 'Invalid request parameters', 400);
    }
    
    if (!isValidPhone(phone)) {
      return response(res, false, null, 'Invalid phone number format', 400);
    }
    
    const user = await User.findById(req.user.id);
    if (!user) {
      return response(res, false, null, 'User not found', 404);
    }
    
    // Get plan amount (in a real app, this would come from a database)
    const planAmounts = {
      '1gb': 300,
      '2gb': 500,
      '5gb': 1200,
      '10gb': 2000
    };
    
    const amount = planAmounts[plan];
    if (!amount) {
      return response(res, false, null, 'Invalid plan selected', 400);
    }
    
    // Check wallet balance if paying with wallet
    if (paymentMethod === 'wallet' && user.walletBalance < amount) {
      return response(res, false, null, 'Insufficient wallet balance', 400);
    }
    
    const reference = generateReference('DATA');
    
    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: 'data',
      amount,
      reference,
      status: 'pending',
      metadata: { network, phone, plan, paymentMethod }
    });
    
    await transaction.save();
    
    // Process payment
    if (paymentMethod === 'wallet') {
      // Deduct from wallet
      user.walletBalance -= amount;
      await user.save();
      
      // Process data purchase
      const result = await processDataPurchase(network, phone, plan, reference);
      
      // Update transaction status
      transaction.status = result.success ? 'successful' : 'failed';
      await transaction.save();
      
      if (result.success) {
        // Create notification
        await new Notification({
          userId: user._id,
          title: 'Data Purchase Successful',
          message: `You purchased ${plan} data for ${phone}`
        }).save();
        
        response(res, true, { reference }, 'Data purchase successful');
      } else {
        // Refund wallet if failed
        user.walletBalance += amount;
        await user.save();
        
        // Create notification
        await new Notification({
          userId: user._id,
          title: 'Data Purchase Failed',
          message: `Your data purchase for ${phone} failed. Amount refunded.`
        }).save();
        
        response(res, false, null, result.message || 'Data purchase failed', 400);
      }
    } else {
      // Initialize payment with Paystack
      const initRes = await axios.post(PAYSTACK_INIT_URL, {
        amount: amount * 100, // Convert to kobo
        email: user.email,
        metadata: {
          userId: user._id,
          serviceType: 'data',
          reference,
          network,
          phone,
          plan
        },
        callback_url: `${APP_BASE_URL}/payment-success.html`
      }, {
        headers: { Authorization: `Bearer ${PAYSTACK_SECRET}` }
      });
      
      response(res, true, {
        authorization_url: initRes?.data?.data?.authorization_url,
        reference
      }, 'Data purchase initiated');
    }
  } catch (err) {
    console.error('DATA_ERR', err);
    response(res, false, null, 'Data purchase failed', 500);
  }
});

app.post('/api/services/electricity', authenticateToken, async (req, res) => {
  try {
    const { disco, meter, meterType, amount, phone, email, paymentMethod } = req.body;
    
    if (!disco || !meter || !meterType || !amount || amount < 1000) {
      return response(res, false, null, 'Invalid request parameters', 400);
    }
    
    if (phone && !isValidPhone(phone)) {
      return response(res, false, null, 'Invalid phone number format', 400);
    }
    
    if (email && !isValidEmail(email)) {
      return response(res, false, null, 'Invalid email format', 400);
    }
    
    const user = await User.findById(req.user.id);
    if (!user) {
      return response(res, false, null, 'User not found', 404);
    }
    
    // Check wallet balance if paying with wallet
    if (paymentMethod === 'wallet' && user.walletBalance < amount) {
      return response(res, false, null, 'Insufficient wallet balance', 400);
    }
    
    const reference = generateReference('ELECTRICITY');
    
    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: 'electricity',
      amount,
      reference,
      status: 'pending',
      metadata: { disco, meter, meterType, phone, email, paymentMethod }
    });
    
    await transaction.save();
    
    // Process payment
    if (paymentMethod === 'wallet') {
      // Deduct from wallet
      user.walletBalance -= amount;
      await user.save();
      
      // Process electricity payment
      const result = await processElectricityPayment(disco, meter, meterType, amount, reference);
      
      // Update transaction status
      transaction.status = result.success ? 'successful' : 'failed';
      transaction.metadata.token = result.token;
      await transaction.save();
      
      if (result.success) {
        // Send token via email and SMS
        if (email) {
          await sendEmail(
            email,
            'Electricity Token',
            `<h1>Your Electricity Token</h1>
            <p>Token: <strong>${result.token}</strong></p>
            <p>Amount: ₦${amount}</p>
            <p>Reference: ${reference}</p>`
          );
        }
        
        // Send SMS (in a real app, you would integrate with an SMS service)
        console.log(`SMS sent to ${phone}: Your electricity token is ${result.token}`);
        
        // Create notification
        await new Notification({
          userId: user._id,
          title: 'Electricity Payment Successful',
          message: `Your electricity payment of ₦${amount} was successful. Token: ${result.token}`
        }).save();
        
        response(res, true, { 
          reference,
          token: result.token 
        }, 'Electricity payment successful');
      } else {
        // Refund wallet if failed
        user.walletBalance += amount;
        await user.save();
        
        // Create notification
        await new Notification({
          userId: user._id,
          title: 'Electricity Payment Failed',
          message: `Your electricity payment failed. Amount refunded.`
        }).save();
        
        response(res, false, null, result.message || 'Electricity payment failed', 400);
      }
    } else {
      // Initialize payment with Paystack
      const initRes = await axios.post(PAYSTACK_INIT_URL, {
        amount: amount * 100, // Convert to kobo
        email: user.email,
        metadata: {
          userId: user._id,
          serviceType: 'electricity',
          reference,
          disco,
          meter,
          meterType,
          phone,
          email
        },
        callback_url: `${APP_BASE_URL}/payment-success.html`
      }, {
        headers: { Authorization: `Bearer ${PAYSTACK_SECRET}` }
      });
      
      response(res, true, {
        authorization_url: initRes?.data?.data?.authorization_url,
        reference
      }, 'Electricity payment initiated');
    }
  } catch (err) {
    console.error('ELECTRICITY_ERR', err);
    response(res, false, null, 'Electricity payment failed', 500);
  }
});

app.post('/api/services/tv', authenticateToken, async (req, res) => {
  try {
    const { provider, smartcard, plan, phone, email, paymentMethod } = req.body;
    
    if (!provider || !smartcard || !plan) {
      return response(res, false, null, 'Invalid request parameters', 400);
    }
    
    if (phone && !isValidPhone(phone)) {
      return response(res, false, null, 'Invalid phone number format', 400);
    }
    
    if (email && !isValidEmail(email)) {
      return response(res, false, null, 'Invalid email format', 400);
    }
    
    const user = await User.findById(req.user.id);
    if (!user) {
      return response(res, false, null, 'User not found', 404);
    }
    
    // Get plan amount (in a real app, this would come from a database)
    const planAmounts = {
      'dstv1': 24000,
      'dstv2': 15700,
      'dstv3': 10500,
      'dstv4': 6800,
      'gotv1': 5500,
      'gotv2': 3280,
      'gotv3': 2460,
      'startimes1': 4200,
      'startimes2': 2600,
      'startimes3': 1900
    };
    
    const amount = planAmounts[plan];
    if (!amount) {
      return response(res, false, null, 'Invalid plan selected', 400);
    }
    
    // Check wallet balance if paying with wallet
    if (paymentMethod === 'wallet' && user.walletBalance < amount) {
      return response(res, false, null, 'Insufficient wallet balance', 400);
    }
    
    const reference = generateReference('TV');
    
    // Create transaction record
    const transaction = new Transaction({
      userId: user._id,
      type: 'tv',
      amount,
      reference,
      status: 'pending',
      metadata: { provider, smartcard, plan, phone, email, paymentMethod }
    });
    
    await transaction.save();
    
    // Process payment
    if (paymentMethod === 'wallet') {
      // Deduct from wallet
      user.walletBalance -= amount;
      await user.save();
      
      // Process TV subscription
      const result = await processTVSubscription(provider, smartcard, plan, reference);
      
      // Update transaction status
      transaction.status = result.success ? 'successful' : 'failed';
      await transaction.save();
      
      if (result.success) {
        // Send confirmation via email and SMS
        if (email) {
          await sendEmail(
            email,
            'TV Subscription Confirmation',
            `<h1>TV Subscription Successful</h1>
            <p>Provider: ${provider}</p>
            <p>Smartcard: ${smartcard}</p>
            <p>Plan: ${plan}</p>
            <p>Amount: ₦${amount}</p>
            <p>Reference: ${reference}</p>`
          );
        }
        
        // Send SMS (in a real app, you would integrate with an SMS service)
        console.log(`SMS sent to ${phone}: Your TV subscription for ${provider} has been renewed`);
        
        // Create notification
        await new Notification({
          userId: user._id,
          title: 'TV Subscription Successful',
          message: `Your ${provider} subscription has been renewed successfully.`
        }).save();
        
        response(res, true, { 
          reference 
        }, 'TV subscription successful');
      } else {
        // Refund wallet if failed
        user.walletBalance += amount;
        await user.save();
        
        // Create notification
        await new Notification({
          userId: user._id,
          title: 'TV Subscription Failed',
          message: `Your TV subscription failed. Amount refunded.`
        }).save();
        
        response(res, false, null, result.message || 'TV subscription failed', 400);
      }
    } else {
      // Initialize payment with Paystack
      const initRes = await axios.post(PAYSTACK_INIT_URL, {
        amount: amount * 100, // Convert to kobo
        email: user.email,
        metadata: {
          userId: user._id,
          serviceType: 'tv',
          reference,
          provider,
          smartcard,
          plan,
          phone,
          email
        },
        callback_url: `${APP_BASE_URL}/payment-success.html`
      }, {
        headers: { Authorization: `Bearer ${PAYSTACK_SECRET}` }
      });
      
      response(res, true, {
        authorization_url: initRes?.data?.data?.authorization_url,
        reference
      }, 'TV subscription initiated');
    }
  } catch (err) {
    console.error('TV_ERR', err);
    response(res, false, null, 'TV subscription failed', 500);
  }
});

// Transaction Routes
app.get('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 10, type, status } = req.query;
    const skip = (page - 1) * limit;
    
    const filter = { userId: req.user.id };
    if (type) filter.type = type;
    if (status) filter.status = status;
    
    const transactions = await Transaction.find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Transaction.countDocuments(filter);
    
    response(res, true, {
      transactions,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / limit)
      }
    }, 'Transactions retrieved');
  } catch (err) {
    console.error('TRANSACTIONS_ERR', err);
    response(res, false, null, 'Failed to get transactions', 500);
  }
});

app.get('/api/transactions/:reference', authenticateToken, async (req, res) => {
  try {
    const transaction = await Transaction.findOne({ 
      reference: req.params.reference,
      userId: req.user.id 
    });
    
    if (!transaction) {
      return response(res, false, null, 'Transaction not found', 404);
    }
    
    response(res, true, { transaction }, 'Transaction retrieved');
  } catch (err) {
    console.error('TRANSACTION_ERR', err);
    response(res, false, null, 'Failed to get transaction', 500);
  }
});

// Admin Routes
app.get('/api/admin/stats', authenticateToken, authorizeRole(['admin', 'super-admin']), async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalTransactions = await Transaction.countDocuments();
    
    const totalVolume = await Transaction.aggregate([
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    const successfulTransactions = await Transaction.countDocuments({ status: 'successful' });
    const verificationRate = totalTransactions > 0 
      ? (successfulTransactions / totalTransactions) * 100 
      : 0;
    
    response(res, true, {
      totalUsers,
      totalTransactions,
      totalVolume: totalVolume[0]?.total || 0,
      verificationRate: parseFloat(verificationRate.toFixed(1))
    }, 'Admin stats retrieved');
  } catch (err) {
    console.error('ADMIN_STATS_ERR', err);
    response(res, false, null, 'Failed to get admin stats', 500);
  }
});

app.get('/api/admin/users', authenticateToken, authorizeRole(['admin', 'super-admin']), async (req, res) => {
  try {
    const { page = 1, limit = 10, search } = req.query;
    const skip = (page - 1) * limit;
    
    let filter = {};
    if (search) {
      filter = {
        $or: [
          { name: { $regex: search, $options: 'i' } },
          { email: { $regex: search, $options: 'i' } }
        ]
      };
    }
    
    const users = await User.find(filter)
      .select('-password')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await User.countDocuments(filter);
    
    response(res, true, {
      users,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / limit)
      }
    }, 'Users retrieved');
  } catch (err) {
    console.error('ADMIN_USERS_ERR', err);
    response(res, false, null, 'Failed to get users', 500);
  }
});

app.put('/api/admin/users/:id', authenticateToken, authorizeRole(['admin', 'super-admin']), async (req, res) => {
  try {
    const { name, email, phone, role, isActive } = req.body;
    
    const user = await User.findById(req.params.id);
    if (!user) {
      return response(res, false, null, 'User not found', 404);
    }
    
    // Update user fields
    if (name) user.name = name;
    if (email) {
      if (!isValidEmail(email)) {
        return response(res, false, null, 'Invalid email format', 400);
      }
      user.email = email;
    }
    if (phone) {
      if (!isValidPhone(phone)) {
        return response(res, false, null, 'Invalid phone number format', 400);
      }
      user.phone = phone;
    }
    if (role) user.role = role;
    if (typeof isActive === 'boolean') user.isActive = isActive;
    
    await user.save();
    
    response(res, true, { user }, 'User updated successfully');
  } catch (err) {
    console.error('ADMIN_UPDATE_USER_ERR', err);
    response(res, false, null, 'Failed to update user', 500);
  }
});

app.post('/api/admin/users/reset-password/:id', authenticateToken, authorizeRole(['admin', 'super-admin']), async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return response(res, false, null, 'User not found', 404);
    }
    
    // Generate random password
    const newPassword = Math.random().toString(36).slice(-8);
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    
    user.password = hashedPassword;
    await user.save();
    
    // Send email with new password
    await sendEmail(
      user.email,
      'Your Password Has Been Reset',
      `<h1>Password Reset</h1>
      <p>Your password has been reset by an administrator.</p>
      <p>Your new password is: <strong>${newPassword}</strong></p>
      <p>Please change your password after logging in.</p>`
    );
    
    response(res, true, null, 'Password reset successfully');
  } catch (err) {
    console.error('ADMIN_RESET_PASSWORD_ERR', err);
    response(res, false, null, 'Failed to reset password', 500);
  }
});

app.get('/api/admin/transactions', authenticateToken, authorizeRole(['admin', 'super-admin']), async (req, res) => {
  try {
    const { page = 1, limit = 10, type, status, userId } = req.query;
    const skip = (page - 1) * limit;
    
    let filter = {};
    if (type) filter.type = type;
    if (status) filter.status = status;
    if (userId) filter.userId = userId;
    
    const transactions = await Transaction.find(filter)
      .populate('userId', 'name email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Transaction.countDocuments(filter);
    
    response(res, true, {
      transactions,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / limit)
      }
    }, 'Transactions retrieved');
  } catch (err) {
    console.error('ADMIN_TRANSACTIONS_ERR', err);
    response(res, false, null, 'Failed to get transactions', 500);
  }
});

app.put('/api/admin/transactions/:id/verify', authenticateToken, authorizeRole(['admin', 'super-admin']), async (req, res) => {
  try {
    const transaction = await Transaction.findById(req.params.id);
    if (!transaction) {
      return response(res, false, null, 'Transaction not found', 404);
    }
    
    transaction.status = 'successful';
    await transaction.save();
    
    response(res, true, null, 'Transaction verified successfully');
  } catch (err) {
    console.error('ADMIN_VERIFY_TRANSACTION_ERR', err);
    response(res, false, null, 'Failed to verify transaction', 500);
  }
});

app.get('/api/admin/commissions', authenticateToken, authorizeRole(['admin', 'super-admin']), async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    const skip = (page - 1) * limit;
    
    const commissions = await Commission.find()
      .populate('userId', 'name email')
      .populate('transactionId', 'reference amount')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Commission.countDocuments();
    
    response(res, true, {
      commissions,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / limit)
      }
    }, 'Commissions retrieved');
  } catch (err) {
    console.error('ADMIN_COMMISSIONS_ERR', err);
    response(res, false, null, 'Failed to get commissions', 500);
  }
});

app.post('/api/admin/commissions/pay/:id', authenticateToken, authorizeRole(['admin', 'super-admin']), async (req, res) => {
  try {
    const commission = await Commission.findById(req.params.id);
    if (!commission) {
      return response(res, false, null, 'Commission not found', 404);
    }
    
    commission.status = 'paid';
    await commission.save();
    
    response(res, true, null, 'Commission marked as paid');
  } catch (err) {
    console.error('ADMIN_PAY_COMMISSION_ERR', err);
    response(res, false, null, 'Failed to pay commission', 500);
  }
});

app.get('/api/admin/notifications', authenticateToken, authorizeRole(['admin', 'super-admin']), async (req, res) => {
  try {
    const notifications = await Notification.find()
      .populate('userId', 'name email')
      .sort({ createdAt: -1 })
      .limit(50);
    
    response(res, true, { notifications }, 'Notifications retrieved');
  } catch (err) {
    console.error('ADMIN_NOTIFICATIONS_ERR', err);
    response(res, false, null, 'Failed to get notifications', 500);
  }
});

app.post('/api/admin/notifications', authenticateToken, authorizeRole(['admin', 'super-admin']), async (req, res) => {
  try {
    const { title, message, userId } = req.body;
    
    if (!title || !message) {
      return response(res, false, null, 'Title and message are required', 400);
    }
    
    const notification = new Notification({
      userId,
      title,
      message
    });
    
    await notification.save();
    
    response(res, true, null, 'Notification sent successfully');
  } catch (err) {
    console.error('ADMIN_SEND_NOTIFICATION_ERR', err);
    response(res, false, null, 'Failed to send notification', 500);
  }
});

// Service Processing Functions (Simplified for demo)
async function processAirtimePurchase(network, phone, amount, reference) {
  // In a real app, this would integrate with a VTpass or similar API
  console.log(`Processing airtime purchase: ${network} ${phone} ₦${amount} ${reference}`);
  
  // Simulate API call
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  // Simulate success (90% success rate)
  if (Math.random() < 0.9) {
    return { success: true };
  } else {
    return { success: false, message: 'Failed to process airtime purchase' };
  }
}

async function processDataPurchase(network, phone, plan, reference) {
  // In a real app, this would integrate with a VTpass or similar API
  console.log(`Processing data purchase: ${network} ${phone} ${plan} ${reference}`);
  
  // Simulate API call
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  // Simulate success (90% success rate)
  if (Math.random() < 0.9) {
    return { success: true };
  } else {
    return { success: false, message: 'Failed to process data purchase' };
  }
}

async function processElectricityPayment(disco, meter, meterType, amount, reference) {
  // In a real app, this would integrate with a VTpass or similar API
  console.log(`Processing electricity payment: ${disco} ${meter} ${meterType} ₦${amount} ${reference}`);
  
  // Simulate API call
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  // Simulate success (90% success rate)
  if (Math.random() < 0.9) {
    // Generate a random token
    const token = Math.random().toString(36).substring(2, 15).toUpperCase();
    return { success: true, token };
  } else {
    return { success: false, message: 'Failed to process electricity payment' };
  }
}

async function processTVSubscription(provider, smartcard, plan, reference) {
  // In a real app, this would integrate with a VTpass or similar API
  console.log(`Processing TV subscription: ${provider} ${smartcard} ${plan} ${reference}`);
  
  // Simulate API call
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  // Simulate success (90% success rate)
  if (Math.random() < 0.9) {
    return { success: true };
  } else {
    return { success: false, message: 'Failed to process TV subscription' };
  }
}

// Health check
app.get('/health', (req, res) => {
  response(res, true, { status: 'ok', time: new Date().toISOString() }, 'Health check');
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running in ${process.env.NODE_ENV || 'development'} mode on port ${PORT}`);
  console.log(`CORS configured for: ${allowedOrigins.join(', ')}`);
});