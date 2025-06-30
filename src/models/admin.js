const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const AdminSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  },
  profilePicture: {
    type: String,
    default: null
  },
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

// Hash password before saving
AdminSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

// Method to compare passwords
AdminSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// For AdminSchema - Add the same methods
AdminSchema.methods.togglePinChat = function (targetUsername) {
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

// Method to check if chat is pinned for Admin schema
AdminSchema.methods.isChatPinned = function (targetUsername) {
  return this.pinnedChats.some(pin => pin.username === targetUsername);
};

// Method to get pinned chats for Admin schema
AdminSchema.methods.getPinnedChats = function () {
  return this.pinnedChats
    .sort((a, b) => new Date(a.pinnedAt) - new Date(b.pinnedAt))
    .map(pin => pin.username);
};

module.exports = mongoose.model('Admin', AdminSchema);
