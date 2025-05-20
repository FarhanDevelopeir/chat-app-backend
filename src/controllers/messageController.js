const Message = require('../models/Message');

// Get messages between users
exports.getMessages = async (req, res) => {
  try {
    const { sender, receiver } = req.params;
    
    const messages = await Message.find({
      $or: [
        { sender, receiver },
        { sender: receiver, receiver: sender }
      ]
    }).sort({ createdAt: 1 });
    
    res.status(200).json(messages);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};