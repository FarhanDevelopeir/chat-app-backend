const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  password: {
    type: String,
    required: false
  },
  deviceId: {
    type: String,
    // required: true
  },
  profilePicture: {
    type: String,
    default: null
  },
  isOnline: {
    type: Boolean,
    default: false
  },
  lastSeen: {
    type: Date,
    default: Date.now
  },
  ipAddress: {
    type: String,
    default: null
  },
  loginHistory: [{
    ipAddress: String,
    loginTime: Date,
    deviceId: String
  }],
}, { timestamps: true });

UserSchema.methods.comparePassword = async function (candidatePassword) {
  return this.password === candidatePassword;
};

// Optional: Add method to track login history
UserSchema.methods.addLoginHistory = function (ipAddress, deviceId) {
  this.loginHistory.push({
    ipAddress,
    loginTime: new Date(),
    deviceId
  });

  // Keep only last 50 login records
  if (this.loginHistory.length > 50) {
    this.loginHistory = this.loginHistory.slice(-50);
  }
}

module.exports = mongoose.model('User', UserSchema);