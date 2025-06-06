const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');

router.get('/', userController.getAllUsers);
router.get('/:username', userController.getUserByUsername);
router.post('/createAdmin', userController.createAdmin);

module.exports = router;