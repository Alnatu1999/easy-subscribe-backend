// db.js - CommonJS version
const mongoose = require('mongoose');

// Database Connection
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/easysubscribe', {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    console.log('MongoDB connected successfully');
  } catch (error) {
    console.error('MongoDB connection error:', error);
    process.exit(1);
  }
};

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  phone: { type: String },
  role: { type: String, enum: ['user', 'admin', 'super-admin'], default: 'user' },
  walletBalance: { type: Number, default: 0 },
  isActive: { type: Boolean, default: true },
  resetPasswordToken: { type: String },
  resetPasswordExpires: { type: Date },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { timestamps: true });

userSchema.index({ email: 1 });
userSchema.index({ role: 1 });
userSchema.index({ createdAt: -1 });

// Transaction Schema - UPDATED to include 'funding' type
const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { 
    type: String, 
    enum: ['airtime', 'data', 'electricity', 'tv', 'funding'], 
    required: true 
  },
  amount: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'successful', 'failed'], default: 'pending' },
  reference: { type: String, unique: true },
  metadata: { 
    type: Object,
    default: {}
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { timestamps: true });

// Indexes for Transaction Schema
transactionSchema.index({ userId: 1 });
transactionSchema.index({ reference: 1 });
transactionSchema.index({ status: 1 });
transactionSchema.index({ type: 1 });
transactionSchema.index({ createdAt: -1 });
// Additional indexes for funding-related queries
transactionSchema.index({ type: 1, status: 1 });
transactionSchema.index({ 'metadata.paymentMethod': 1 });
transactionSchema.index({ 'metadata.requestedBy': 1 });
transactionSchema.index({ 'metadata.fundedBy': 1 });
transactionSchema.index({ 'metadata.approvedBy': 1 });
transactionSchema.index({ 'metadata.rejectedBy': 1 });

// Admin Role Schema
const adminRoleSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  permissions: [String],
  description: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { timestamps: true });

adminRoleSchema.index({ name: 1 });

// Notification Schema
const notificationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  message: { type: String, required: true },
  isRead: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { timestamps: true });

notificationSchema.index({ userId: 1 });
notificationSchema.index({ isRead: 1 });
notificationSchema.index({ createdAt: -1 });

// Commission Schema
const commissionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  percentage: { type: Number, required: true },
  transactionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction' },
  status: { type: String, enum: ['pending', 'paid'], default: 'pending' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { timestamps: true });

commissionSchema.index({ userId: 1 });
commissionSchema.index({ status: 1 });
commissionSchema.index({ transactionId: 1 });
commissionSchema.index({ createdAt: -1 });

// Create Models
const User = mongoose.model('User', userSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const AdminRole = mongoose.model('AdminRole', adminRoleSchema);
const Notification = mongoose.model('Notification', notificationSchema);
const Commission = mongoose.model('Commission', commissionSchema);

module.exports = {
  connectDB,
  User,
  Transaction,
  AdminRole,
  Notification,
  Commission
};