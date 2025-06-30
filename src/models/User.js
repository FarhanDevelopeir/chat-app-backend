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
  isPasswordChanged: {
    type: Boolean,
    default: false
  },
  isOnline: {
    type: Boolean,
    default: false
  },
  isSubAdmin: {
    type: Boolean,
    default: false
  },
  assignedUsers: [{
    type: String, // Store usernames
    ref: 'User'
  }],
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
  pinnedChats: [{
    username: {
      type: String,
      required: true
    },
    pinnedAt: {
      type: Date,
      default: Date.now
    }
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

// Method to get users assigned to this sub-admin
UserSchema.methods.getAssignedUsers = async function () {
  if (!this.isSubAdmin) return [];

  const User = mongoose.model('User');
  return await User.find({
    username: { $in: this.assignedUsers },
    isSubAdmin: false
  }, 'username isOnline lastSeen profilePicture ipAddress');
};


UserSchema.methods.togglePinChat = function(targetUsername) {
  const existingPinIndex = this.pinnedChats.findIndex(
    pin => pin.username === targetUsername
  );
  
  if (existingPinIndex > -1) {
    // Unpin
    this.pinnedChats.splice(existingPinIndex, 1);
    return false; // unpinned
  } else {
    // Pin
    this.pinnedChats.push({
      username: targetUsername,
      pinnedAt: new Date()
    });
    return true; // pinned
  }
};

// Method to check if chat is pinned for User schema
UserSchema.methods.isChatPinned = function(targetUsername) {
  return this.pinnedChats.some(pin => pin.username === targetUsername);
};

// Method to get pinned chats for User schema
UserSchema.methods.getPinnedChats = function() {
  return this.pinnedChats
    .sort((a, b) => new Date(a.pinnedAt) - new Date(b.pinnedAt))
    .map(pin => pin.username);
};

module.exports = mongoose.model('User', UserSchema);