const express = require('express');
const router = express.Router();
const messageController = require('../controllers/messageController');

router.get('/:sender/:receiver', messageController.getMessages);

module.exports = router;