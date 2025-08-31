// server.js - Combined version with VTU service and TV routes
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const dotenv = require('dotenv');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const axios = require('axios'); // Added for VTU service
const { connectDB, User, Transaction, AdminRole, Notification, Commission } = require('./db.js');
dotenv.config();

const app = express();
app.use(helmet());

// Enhanced CORS configuration - UPDATED FOR PRODUCTION
const allowedOrigins = [
  'http://localhost:5173',
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  process.env.FRONTEND_URL || 'https://easy-subscribe-frontend.onrender.com'
];

// Remove duplicate origins
const uniqueOrigins = [...new Set(allowedOrigins)];
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    // Allow requests with origin 'null' (sandboxed iframes, etc.)
    if (origin === 'null') return callback(null, true);
    
    if (uniqueOrigins.indexOf(origin) !== -1) {
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

// Connect to Database
connectDB();

// Constants - UPDATED FOR PRODUCTION
const PORT = process.env.PORT || 5001;
const APP_BASE_URL = process.env.APP_BASE_URL || (process.env.NODE_ENV === 'production' 
  ? 'https://easy-subscribe-frontend.onrender.com' // Updated with actual URL
  : 'http://localhost:5173');
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'your-refresh-secret';

// VTU.ng API configuration
const VTU_BASE_URL = 'https://vtu.ng/wp-json';
const VTU_AUTH_URL = `${VTU_BASE_URL}/jwt-auth/v1/token`;
const VTU_API_URL = `${VTU_BASE_URL}/api/v2`;

// Store credentials securely (use environment variables in production)
const VTU_USERNAME = process.env.VTU_USERNAME || 'your_vtu_username';
const VTU_PASSWORD = process.env.VTU_PASSWORD || 'your_vtu_password';
const VTU_USER_PIN = process.env.VTU_USER_PIN || 'your_user_pin';

// Cache for access token
let accessToken = null;
let tokenExpiry = null;

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

// VTU Service Functions
// Get access token from VTU.ng
async function getAccessToken() {
  // Check if we have a valid token
  if (accessToken && tokenExpiry && new Date() < tokenExpiry) {
    return accessToken;
  }
  try {
    const response = await axios.post(VTU_AUTH_URL, {
      username: VTU_USERNAME,
      password: VTU_PASSWORD
    });
    if (response.data.token) {
      accessToken = response.data.token;
      // Token expires after 7 days, set expiry to 6 days for safety
      tokenExpiry = new Date(Date.now() + 6 * 24 * 60 * 60 * 1000);
      return accessToken;
    } else {
      throw new Error('Failed to get access token');
    }
  } catch (error) {
    console.error('VTU Authentication Error:', error.response?.data || error.message);
    throw new Error('Authentication with VTU.ng failed');
  }
}

// Validate smartcard format based on provider
function validateSmartcardFormat(smartcard, provider) {
  if (!smartcard || typeof smartcard !== 'string') {
    return { valid: false, message: 'Smartcard number is required' };
  }
  
  // Remove any spaces or dashes
  const cleanCard = smartcard.replace(/[\s-]/g, '');
  
  // Provider-specific validation
  switch (provider.toLowerCase()) {
    case 'dstv':
      if (!/^\d{10,11}$/.test(cleanCard)) {
        return { valid: false, message: 'DStv smartcard must be 10-11 digits' };
      }
      break;
    case 'gotv':
      if (!/^\d{10}$/.test(cleanCard)) {
        return { valid: false, message: 'GOtv smartcard must be 10 digits' };
      }
      break;
    case 'startimes':
      if (!/^\d{10,12}$/.test(cleanCard)) {
        return { valid: false, message: 'StarTimes smartcard must be 10-12 digits' };
      }
      break;
    default:
      // Generic validation for unknown providers
      if (!/^\d{8,15}$/.test(cleanCard)) {
        return { valid: false, message: 'Invalid smartcard number format' };
      }
  }
  
  return { valid: true, message: 'Valid format' };
}

// Get TV variations (public endpoint, no auth required)
async function getTvVariations(serviceId = null) {
  try {
    let url = `${VTU_API_URL}/variations/tv`;
    if (serviceId) {
      url += `?service_id=${serviceId}`;
    }
    const response = await axios.get(url);
    return response.data;
  } catch (error) {
    console.error('Error fetching TV variations:', error.response?.data || error.message);
    throw new Error('Failed to fetch TV variations');
  }
}

// Verify customer (smartcard/IUC number)
async function verifyCustomer(customerId, serviceId) {
  // First, validate the format locally
  const formatValidation = validateSmartcardFormat(customerId, serviceId);
  if (!formatValidation.valid) {
    return {
      code: 'error',
      message: formatValidation.message
    };
  }
  
  try {
    const token = await getAccessToken();
    
    const response = await axios.post(
      `${VTU_API_URL}/verify-customer`,
      {
        customer_id: customerId,
        service_id: serviceId
      },
      {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      }
    );
    return response.data;
  } catch (error) {
    console.error('Error verifying customer:', error.response?.data || error.message);
    
    // Provide more specific error messages based on the error
    if (error.response && error.response.data) {
      const vtuError = error.response.data;
      
      if (vtuError.message && vtuError.message.toLowerCase().includes('invalid')) {
        return {
          code: 'error',
          message: 'Invalid smartcard number'
        };
      } else if (vtuError.message && vtuError.message.toLowerCase().includes('not found')) {
        return {
          code: 'error',
          message: 'Smartcard not found'
        };
      } else if (vtuError.message && vtuError.message.toLowerCase().includes('does not exist')) {
        return {
          code: 'error',
          message: 'Smartcard does not exist'
        };
      }
    }
    
    return {
      code: 'error',
      message: 'Failed to verify customer details'
    };
  }
}

// Purchase TV subscription
async function purchaseTvSubscription(requestId, customerId, serviceId, variationId, subscriptionType = 'change') {
  try {
    // Validate smartcard format before making the purchase
    const formatValidation = validateSmartcardFormat(customerId, serviceId);
    if (!formatValidation.valid) {
      return {
        code: 'error',
        message: formatValidation.message
      };
    }
    
    const token = await getAccessToken();
    
    const response = await axios.post(
      `${VTU_API_URL}/tv`,
      {
        request_id: requestId,
        customer_id: customerId,
        service_id: serviceId,
        variation_id: variationId,
        subscription_type: subscriptionType
      },
      {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      }
    );
    return response.data;
  } catch (error) {
    console.error('Error purchasing TV subscription:', error.response?.data || error.message);
    
    // Provide more specific error messages based on the error
    if (error.response && error.response.data) {
      const vtuError = error.response.data;
      
      if (vtuError.message && vtuError.message.toLowerCase().includes('invalid customer')) {
        return {
          code: 'error',
          message: 'Invalid smartcard number'
        };
      } else if (vtuError.message && vtuError.message.toLowerCase().includes('insufficient balance')) {
        return {
          code: 'error',
          message: 'Insufficient balance for this subscription'
        };
      }
    }
    
    return {
      code: 'error',
      message: 'Failed to purchase TV subscription'
    };
  }
}

// Requery order status
async function requeryOrder(requestId) {
  try {
    const token = await getAccessToken();
    
    const response = await axios.post(
      `${VTU_API_URL}/requery`,
      {
        request_id: requestId
      },
      {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      }
    );
    return response.data;
  } catch (error) {
    console.error('Error requerying order:', error.response?.data || error.message);
    throw new Error('Failed to requery order status');
  }
}

// Verify webhook signature
function verifyWebhookSignature(payload, signature) {
  const computedSignature = crypto
    .createHmac('sha256', VTU_USER_PIN)
    .update(JSON.stringify(payload))
    .digest('hex');
  
  return crypto.timingSafeEqual(
    Buffer.from(computedSignature, 'hex'),
    Buffer.from(signature, 'hex')
  );
}

// Helper function to map provider names to service IDs
function mapProviderToServiceId(provider) {
  switch (provider.toLowerCase()) {
    case 'dstv':
      return 'dstv';
    case 'gotv':
      return 'gotv';
    case 'startimes':
      return 'startimes';
    default:
      return null;
  }
}

// TV Routes (integrated from tvRoutes.js)
// Get TV variations
app.get('/api/services/tv-variations', async (req, res) => {
  try {
    const { provider } = req.query;
    
    if (!provider) {
      return res.status(400).json({
        success: false,
        message: 'Provider is required'
      });
    }
    
    // Map provider names to VTU service IDs
    const serviceId = mapProviderToServiceId(provider);
    if (!serviceId) {
      return res.status(400).json({
        success: false,
        message: 'Invalid provider'
      });
    }
    
    const variations = await getTvVariations(serviceId);
    
    if (variations.code === 'success') {
      return res.json({
        success: true,
        data: variations.data
      });
    } else {
      return res.status(400).json({
        success: false,
        message: variations.message || 'Failed to fetch TV variations'
      });
    }
  } catch (error) {
    console.error('Error fetching TV variations:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Verify TV customer
app.get('/api/services/tv-customer', async (req, res) => {
  try {
    const { provider, smartcard } = req.query;
    
    if (!provider || !smartcard) {
      return res.status(400).json({
        success: false,
        message: 'Provider and smartcard are required'
      });
    }
    
    // Map provider names to VTU service IDs
    const serviceId = mapProviderToServiceId(provider);
    if (!serviceId) {
      return res.status(400).json({
        success: false,
        message: 'Invalid provider'
      });
    }
    
    const customer = await verifyCustomer(smartcard, serviceId);
    
    if (customer.code === 'success') {
      // Transform the response to match frontend expectations
      const customerData = {
        customerName: customer.data.Customer_Name || customer.data.customer_name || 'Not available',
        currentPlan: customer.data.Current_Package || customer.data.current_package || 'Not available'
      };
      
      return res.json({
        success: true,
        data: customerData
      });
    } else {
      return res.status(400).json({
        success: false,
        message: customer.message || 'Failed to verify customer'
      });
    }
  } catch (error) {
    console.error('Error verifying customer:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Purchase TV subscription
app.post('/api/services/tv', authenticateToken, async (req, res) => {
  try {
    const { provider, smartcard, plan, phone, email } = req.body;
    
    if (!provider || !smartcard || !plan || !phone) {
      return res.status(400).json({
        success: false,
        message: 'All fields are required'
      });
    }
    
    // Map provider names to VTU service IDs
    const serviceId = mapProviderToServiceId(provider);
    if (!serviceId) {
      return res.status(400).json({
        success: false,
        message: 'Invalid provider'
      });
    }
    
    // Generate a unique request ID
    const requestId = `TV-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
    
    const result = await purchaseTvSubscription(
      requestId,
      smartcard,
      serviceId,
      plan
    );
    
    if (result.code === 'success') {
      // Transform the response to match frontend expectations
      const transactionData = {
        reference: result.request_id || requestId,
        provider: provider,
        smartcard: smartcard,
        status: result.status || 'success',
        amount: result.amount || 0,
        createdAt: new Date().toISOString()
      };
      
      return res.json({
        success: true,
        data: transactionData,
        message: result.message || 'TV subscription successful'
      });
    } else {
      return res.status(400).json({
        success: false,
        message: result.message || 'Failed to purchase TV subscription'
      });
    }
  } catch (error) {
    console.error('Error purchasing TV subscription:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error'
    });
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

// User Funding Request Endpoint
app.post('/api/user/fund-request', authenticateToken, async (req, res) => {
  try {
    const { amount, paymentMethod, reference } = req.body;
    
    // Validate input
    if (!amount || amount <= 0) {
      return response(res, false, null, 'Invalid amount', 400);
    }
    
    if (!paymentMethod || !['bank_transfer', 'cash', 'other'].includes(paymentMethod)) {
      return response(res, false, null, 'Invalid payment method', 400);
    }
    
    const user = await User.findById(req.user.id);
    if (!user) {
      return response(res, false, null, 'User not found', 404);
    }
    
    // Create funding request
    const transaction = new Transaction({
      userId: user._id,
      type: 'funding',
      amount,
      reference: reference || generateReference('FUND'),
      status: 'pending',
      metadata: { 
        paymentMethod,
        requestedBy: user._id,
        requestDate: new Date()
      }
    });
    
    await transaction.save();
    
    // Create notification for user
    await new Notification({
      userId: user._id,
      title: 'Funding Request Submitted',
      message: `Your funding request of ₦${amount} has been submitted and is pending approval.`
    }).save();
    
    // Create notification for admins
    const adminUsers = await User.find({ role: { $in: ['admin', 'super-admin'] } });
    for (const admin of adminUsers) {
      await new Notification({
        userId: admin._id,
        title: 'New Funding Request',
        message: `User ${user.name} requested ₦${amount} funding.`
      }).save();
    }
    
    response(res, true, { 
      transactionId: transaction._id,
      reference: transaction.reference 
    }, 'Funding request submitted successfully');
  } catch (err) {
    console.error('FUND_REQUEST_ERR', err);
    response(res, false, null, 'Failed to submit funding request', 500);
  }
});

// Get User Funding Requests
app.get('/api/user/fund-requests', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 10, status } = req.query;
    const skip = (page - 1) * limit;
    
    let filter = { userId: req.user.id, type: 'funding' };
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
    }, 'Funding requests retrieved');
  } catch (err) {
    console.error('GET_USER_FUND_REQUESTS_ERR', err);
    response(res, false, null, 'Failed to get funding requests', 500);
  }
});

// Service Routes
app.post('/api/services/airtime', authenticateToken, async (req, res) => {
  try {
    const { network, phone, amount } = req.body;
    
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
    
    // Check wallet balance
    if (user.walletBalance < amount) {
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
      metadata: { network, phone }
    });
    
    await transaction.save();
    
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
  } catch (err) {
    console.error('AIRTIME_ERR', err);
    response(res, false, null, 'Airtime purchase failed', 500);
  }
});

app.post('/api/services/data', authenticateToken, async (req, res) => {
  try {
    const { network, phone, plan } = req.body;
    
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
    
    // Check wallet balance
    if (user.walletBalance < amount) {
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
      metadata: { network, phone, plan }
    });
    
    await transaction.save();
    
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
  } catch (err) {
    console.error('DATA_ERR', err);
    response(res, false, null, 'Data purchase failed', 500);
  }
});

app.post('/api/services/electricity', authenticateToken, async (req, res) => {
  try {
    const { disco, meter, meterType, amount, phone, email } = req.body;
    
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
    
    // Check wallet balance
    if (user.walletBalance < amount) {
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
      metadata: { disco, meter, meterType, phone, email }
    });
    
    await transaction.save();
    
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
  } catch (err) {
    console.error('ELECTRICITY_ERR', err);
    response(res, false, null, 'Electricity payment failed', 500);
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

// Admin Manual Funding Endpoint
app.post('/api/admin/fund-wallet', authenticateToken, authorizeRole(['admin', 'super-admin']), async (req, res) => {
  try {
    const { userId, amount, note } = req.body;
    
    // Validate input
    if (!userId) {
      return response(res, false, null, 'User ID is required', 400);
    }
    
    if (!amount || amount <= 0) {
      return response(res, false, null, 'Invalid amount', 400);
    }
    
    // Find user
    const user = await User.findById(userId);
    if (!user) {
      return response(res, false, null, 'User not found', 404);
    }
    
    // Create transaction
    const transaction = new Transaction({
      userId: user._id,
      type: 'funding',
      amount,
      reference: generateReference('ADMIN_FUND'),
      status: 'successful',
      metadata: { 
        fundedBy: req.user.id,
        note,
        fundingDate: new Date()
      }
    });
    
    await transaction.save();
    
    // Update user wallet
    user.walletBalance += amount;
    await user.save();
    
    // Create notification for user
    await new Notification({
      userId: user._id,
      title: 'Wallet Funded',
      message: `Your wallet has been funded with ₦${amount} by admin.`
    }).save();
    
    response(res, true, { 
      transactionId: transaction._id,
      reference: transaction.reference,
      newBalance: user.walletBalance
    }, 'Wallet funded successfully');
  } catch (err) {
    console.error('ADMIN_FUND_WALLET_ERR', err);
    response(res, false, null, 'Failed to fund wallet', 500);
  }
});

// Admin Approve Funding Request Endpoint
app.put('/api/admin/fund-request/:id/approve', authenticateToken, authorizeRole(['admin', 'super-admin']), async (req, res) => {
  try {
    const { note } = req.body;
    
    // Find transaction
    const transaction = await Transaction.findById(req.params.id);
    if (!transaction) {
      return response(res, false, null, 'Transaction not found', 404);
    }
    
    // Verify it's a funding request
    if (transaction.type !== 'funding') {
      return response(res, false, null, 'Not a funding transaction', 400);
    }
    
    // Verify it's pending
    if (transaction.status !== 'pending') {
      return response(res, false, null, 'Transaction already processed', 400);
    }
    
    // Find user
    const user = await User.findById(transaction.userId);
    if (!user) {
      return response(res, false, null, 'User not found', 404);
    }
    
    // Update transaction
    transaction.status = 'successful';
    transaction.metadata.approvedBy = req.user.id;
    transaction.metadata.approvalDate = new Date();
    transaction.metadata.note = note;
    await transaction.save();
    
    // Update user wallet
    user.walletBalance += transaction.amount;
    await user.save();
    
    // Create notification for user
    await new Notification({
      userId: user._id,
      title: 'Funding Request Approved',
      message: `Your funding request of ₦${transaction.amount} has been approved.`
    }).save();
    
    response(res, true, { 
      transactionId: transaction._id,
      reference: transaction.reference,
      newBalance: user.walletBalance
    }, 'Funding request approved successfully');
  } catch (err) {
    console.error('APPROVE_FUND_REQUEST_ERR', err);
    response(res, false, null, 'Failed to approve funding request', 500);
  }
});

// Admin Reject Funding Request Endpoint
app.put('/api/admin/fund-request/:id/reject', authenticateToken, authorizeRole(['admin', 'super-admin']), async (req, res) => {
  try {
    const { reason } = req.body;
    
    // Find transaction
    const transaction = await Transaction.findById(req.params.id);
    if (!transaction) {
      return response(res, false, null, 'Transaction not found', 404);
    }
    
    // Verify it's a funding request
    if (transaction.type !== 'funding') {
      return response(res, false, null, 'Not a funding transaction', 400);
    }
    
    // Verify it's pending
    if (transaction.status !== 'pending') {
      return response(res, false, null, 'Transaction already processed', 400);
    }
    
    // Update transaction
    transaction.status = 'failed';
    transaction.metadata.rejectedBy = req.user.id;
    transaction.metadata.rejectionDate = new Date();
    transaction.metadata.rejectionReason = reason;
    await transaction.save();
    
    // Create notification for user
    await new Notification({
      userId: transaction.userId,
      title: 'Funding Request Rejected',
      message: `Your funding request of ₦${transaction.amount} was rejected. Reason: ${reason || 'Not specified'}`
    }).save();
    
    response(res, true, { 
      transactionId: transaction._id,
      reference: transaction.reference
    }, 'Funding request rejected');
  } catch (err) {
    console.error('REJECT_FUND_REQUEST_ERR', err);
    response(res, false, null, 'Failed to reject funding request', 500);
  }
});

// Get Funding Requests (Admin)
app.get('/api/admin/fund-requests', authenticateToken, authorizeRole(['admin', 'super-admin']), async (req, res) => {
  try {
    const { page = 1, limit = 10, status } = req.query;
    const skip = (page - 1) * limit;
    
    let filter = { type: 'funding' };
    if (status) filter.status = status;
    
    const transactions = await Transaction.find(filter)
      .populate('userId', 'name email')
      .populate('metadata.fundedBy', 'name')
      .populate('metadata.approvedBy', 'name')
      .populate('metadata.rejectedBy', 'name')
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
    }, 'Funding requests retrieved');
  } catch (err) {
    console.error('GET_FUND_REQUESTS_ERR', err);
    response(res, false, null, 'Failed to get funding requests', 500);
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

// Webhook endpoint for VTU.ng
app.post('/api/webhooks/vtu', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    const signature = req.headers['x-signature'];
    const payload = JSON.parse(req.body);
    
    // Verify the webhook signature
    const isValid = verifyWebhookSignature(payload, signature);
    
    if (!isValid) {
      return response(res, false, null, 'Invalid signature', 403);
    }
    
    // Process the webhook
    const { order_id, status, request_id } = payload;
    
    // Find the transaction by reference
    const transaction = await Transaction.findOne({ reference: request_id });
    
    if (transaction) {
      // Update transaction status
      if (status === 'completed-api') {
        transaction.status = 'successful';
      } else if (status === 'refunded') {
        transaction.status = 'failed';
        
        // Refund the user if not already refunded
        const user = await User.findById(transaction.userId);
        if (user && transaction.status !== 'refunded') {
          user.walletBalance += transaction.amount;
          await user.save();
        }
      }
      
      await transaction.save();
      
      // Create notification
      await new Notification({
        userId: transaction.userId,
        title: `TV Subscription ${status === 'completed-api' ? 'Successful' : 'Failed'}`,
        message: `Your TV subscription ${status === 'completed-api' ? 'was successful' : 'failed and was refunded'}.`
      }).save();
    }
    
    // Respond to VTU.ng
    res.status(200).json({ status: 'success' });
  } catch (error) {
    console.error('VTU Webhook Error:', error);
    res.status(500).json({ status: 'error' });
  }
});

// Health check
app.get('/health', (req, res) => {
  response(res, true, { status: 'ok', time: new Date().toISOString() }, 'Health check');
});

// Start server - UPDATED FOR PRODUCTION
app.listen(PORT, () => {
  console.log(`Server running in ${process.env.NODE_ENV || 'development'} mode on port ${PORT}`);
  console.log(`CORS configured for: ${uniqueOrigins.join(', ')}`);
  
  // Log production URL
  if (process.env.NODE_ENV === 'production') {
    console.log(`Backend live at: https://easy-subscribe-backend.onrender.com`);
    console.log(`Frontend URL should be set to: ${APP_BASE_URL}`);
  }
});