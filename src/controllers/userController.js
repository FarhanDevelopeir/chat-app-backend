const admin = require('../models/admin');
const User = require('../models/User');

// Get all users
exports.getAllUsers = async (req, res) => {
  try {
    const users = await User.find().select('-deviceId');
    res.status(200).json(users);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.createAdmin = async (req, res) => {
  const { username, password } = req.body;

  try {
    // Check if values match env
    if (
      username !== process.env.ADMIN_USERNAME ||
      password !== process.env.ADMIN_PASSWORD
    ) {
      return res.status(403).json({ message: 'Invalid credentials' });
    }

    // Check if admin already exists
    const existingAdmin = await admin.findOne({ username });

    if (existingAdmin) {
      return res.status(409).json({ message: 'Admin already exists' });
    }

    // Create admin
    const newAdmin = new admin({ username, password });
    await newAdmin.save();

    res.status(201).json({ message: 'Admin created successfully' });

  } catch (error) {
    console.error('Error creating admin:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// Get user by username
exports.getUserByUsername = async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username }).select('-deviceId');

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};