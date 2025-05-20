const mongoose = require('mongoose');

const MessageSchema = new mongoose.Schema({
  sender: {
    type: String,
    required: true
  },
  receiver: {
    type: String,
    required: true
  },
  content: {
    type: String,
    required: true
  },
  isRead: {
    type: Boolean,
    default: false
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

module.exports = mongoose.model('Message', MessageSchema);