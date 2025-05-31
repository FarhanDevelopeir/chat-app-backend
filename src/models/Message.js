const mongoose = require('mongoose');

const MessageSchema = new mongoose.Schema({
  sender: {
    type: String,
    required: true
  },
  receiver: {
    type: String,
    default: null
  },
  groupId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Group',
    default: null // null for individual messages
  },
  content: {
    type: String,
    required: true
  },
  isRead: {
    type: Boolean,
    default: false
  },
  reactions: {
    type: Map,
    of: [String], // Array of usernames who reacted with each emoji
    default: new Map()
  },
  // In your Message model
  replyTo: {
    messageId: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' },
    content: String,
    sender: String
  },
  file: {
    name: { type: String },
    type: { type: String },
    size: { type: Number },
    url: { type: String }
  },
  audio: {
    name: { type: String },
    data: { type: String },  // Base64 encoded audio data
    size: { type: Number },
    duration: { type: Number }  // Optional: Duration in seconds
  }
}, { timestamps: true });

// Indexes for better performance
MessageSchema.index({ sender: 1, receiver: 1 });
MessageSchema.index({ groupId: 1 });
MessageSchema.index({ createdAt: -1 });

module.exports = mongoose.model('Message', MessageSchema);