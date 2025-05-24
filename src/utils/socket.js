const socketIO = require('socket.io');
const User = require('../models/User');
const Message = require('../models/Message');
// add group model
const Group = require('../models/Group');

require('dotenv').config();


const setupSocket = (server) => {
  const io = socketIO(server, {
    cors: {
      origin: "*",
      methods: ["GET", "POST"]
    }
  });

  // Map to store active connections
  const activeUsers = new Map();

  // Track admin status
  let adminIsOnline = false;

  // Helper to broadcast admin status to all users
  const broadcastAdminStatus = () => {
    io.emit('admin:status', { isOnline: adminIsOnline });
  };

  io.on('connection', (socket) => {
    console.log('A user connected:', socket.id);

    socket.on('admin:createUser', async ({ username, password }) => {
      try {
        const isAdminSocket = Array.from(socket.rooms).includes('admin');
        if (!isAdminSocket) {
          console.log("username", username);
          console.log("password", password);

          socket.emit('admin:userCreated', {
            success: false,
            message: 'Unauthorized. Only admin can create users.'
          });
          return;
        }
        // Find or create user
        let user = await User.findOne({ username });

        if (user) {
          socket.emit('admin:userCreated', {
            success: false,
            message: 'Username already exists'
          });
          return;
        }

        if (!user) {
          user = new User({
            username,
            password,
            // deviceId,
            isOnline: false
          });
        }

        await user.save();

        // Send success response
        socket.emit('admin:userCreated', {
          success: true,
          message: 'User created successfully'
        });

        // Store user details in the active users map
        activeUsers.set(username, {
          socketId: socket.id,
          userId: user._id
        });

        // Send user list to admin
        const allUsers = await User.find({}, 'username isOnline lastSeen');
        io.to('admin').emit('admin:userList', allUsers);

      } catch (error) {
        console.error('Login error:', error);
        // socket.emit('user:loginError', { error: error.message });
        socket.emit('admin:userCreated', {
          success: false,
          message: error.message || 'Failed to create user'
        });
      }
    });


    socket.on('admin:updateUser', async ({ userID, username, password }) => {

      console.log('Update user attempt:', userID, username, password);

      try {
        const isAdminSocket = Array.from(socket.rooms).includes('admin');
        if (!isAdminSocket) {
          socket.emit('admin:userUpdated', {
            success: false,
            message: 'Unauthorized. Only admin can update users.'
          });
          return;
        }

        console.log('Update user attempt:', userID, username, password);

        // Find the user by original username
        let user = await User.findOne({ _id: userID });

        if (!user) {
          socket.emit('admin:userUpdated', {
            success: false,
            message: 'User not found'
          });
          return;
        }

        // Check if new username already exists (if username is being changed)
        // if (username !== originalUsername) {
        //   const existingUser = await User.findOne({ username });
        //   if (existingUser) {
        //     socket.emit('admin:userUpdated', {
        //       success: false,
        //       message: 'Username already exists'
        //     });
        //     return;
        //   }
        // }

        // Update user fields
        user.username = username;
        if (password && password.trim()) {
          user.password = password;
        }

        await user.save();

        // Send success response
        socket.emit('admin:userUpdated', {
          success: true,
          message: 'User updated successfully'
        });

        // Update active users map if username changed
        // if (username !== originalUsername && activeUsers.has(originalUsername)) {
        //   const userData = activeUsers.get(originalUsername);
        //   activeUsers.delete(originalUsername);
        //   activeUsers.set(username, userData);
        // }

        // Send updated user list to admin
        const allUsers = await User.find({}, 'username isOnline lastSeen');
        io.to('admin').emit('admin:userList', allUsers);

      } catch (error) {
        console.error('Update user error:', error);
        socket.emit('admin:userUpdated', {
          success: false,
          message: error.message || 'Failed to update user'
        });
      }
    });

    // User authentication/login
    socket.on('user:login', async ({ username, password, deviceId }) => {
      console.log('User login attempt:', username, password);

      try {
        // Find or create user
        let user = await User.findOne({ username, password });

        // If user doesn't exist
        if (!user) {
          socket.emit('user:loginError', {
            error: 'Invalid username or password'
          });
          return;
        }

        // Check password
        const isPasswordValid = await user.comparePassword(password);
        if (!isPasswordValid) {
          socket.emit('user:loginError', {
            error: 'Invalid username or password'
          });
          return;
        }

        // Update user status
        user.deviceId = deviceId;
        user.isOnline = true;
        user.lastSeen = Date.now();
        await user.save();


        //   user.lastSeen = Date.now();

        // Store user details in the active users map
        activeUsers.set(username, {
          socketId: socket.id,
          userId: user._id
        });

        // Join a room with the username
        socket.join(username);

        // Send user list to admin
        const allUsers = await User.find({}, 'username isOnline lastSeen');
        console.log('allUsers', allUsers);

        io.to('admin').emit('admin:userList', allUsers);

        // Confirm successful login to the user
        socket.emit('user:loginSuccess', { user });

        // Send admin status to the user
        socket.emit('admin:status', { isOnline: adminIsOnline });

        // Send previous messages to the user
        const messages = await Message.find({
          $or: [
            { sender: username, receiver: "admin" },
            { sender: "admin", receiver: username }
          ]
        }).sort({ createdAt: 1 });

        socket.emit('messages:history', messages);
      } catch (error) {
        console.error('Login error:', error);
        socket.emit('user:loginError', { error: error.message });
      }
    });

    socket.on('user:islogin', async ({ username, deviceId }) => {
      console.log('User islogin attempt:', username, deviceId);

      try {
        // Find or create user
        let user = await User.findOne({ username, deviceId });

        // If user doesn't exist
        if (!user) {
          socket.emit('user:loginError', {
            error: 'Invalid username or password'
          });
          return;
        }

        //   user.lastSeen = Date.now();

        user.isOnline = true;
        user.lastSeen = Date.now();
        await user.save();

        // Store user details in the active users map
        activeUsers.set(username, {
          socketId: socket.id,
          userId: user._id
        });

        // Join a room with the username
        socket.join(username);

        // Send user list to admin
        const allUsers = await User.find({}, 'username isOnline lastSeen');
        io.to('admin').emit('admin:userList', allUsers);

        // Confirm successful login to the user
        socket.emit('user:loginSuccess', { user });

        // Send admin status to the user
        socket.emit('admin:status', { isOnline: adminIsOnline });

        // Send previous messages to the user
        const messages = await Message.find({
          $or: [
            { sender: username, receiver: "admin" },
            { sender: "admin", receiver: username }
          ]
        }).sort({ createdAt: 1 });

        socket.emit('messages:history', messages);
      } catch (error) {
        console.error('Login error:', error);
        socket.emit('user:loginError', { error: error.message });
      }
    });





    // Admin authentication
    socket.on('admin:login', () => {
      socket.join('admin');
      adminIsOnline = true;
      socket.emit('admin:loginSuccess');
      broadcastAdminStatus();

      // Send user list to admin
      User.find({}, 'username isOnline lastSeen')
        .then(users => {
          socket.emit('admin:userList', users);
        })
        .catch(error => {
          console.error('Error fetching users:', error);
        });
    });

    socket.on('admin:loginAttempt', ({ username, password }) => {
      if (
        username === process.env.ADMIN_USERNAME &&
        password === process.env.ADMIN_PASSWORD
      ) {
        console.log('✅ Admin authenticated:', username);
        // socket.join('admin');
        adminIsOnline = true;
        socket.emit('admin:loginSuccess');
        broadcastAdminStatus();

        // Send user list to admin
        User.find({}, 'username isOnline lastSeen')
          .then(users => {
            socket.emit('admin:userList', users);
          })
          .catch(error => {
            console.error('Error fetching users:', error);
          });

        // // Send the current user list or whatever data you want
        // const userList = getAllConnectedUsers(); // You should define this
        // socket.emit('admin:userList', userList);
      } else {
        console.log('❌ Admin login failed');
        socket.emit('admin:loginFailure');
      }
    });

    // Admin selects a user to chat with
    socket.on('admin:selectUser', async (username) => {
      try {
        // Get chat history with the selected user
        const messages = await Message.find({
          $or: [
            { sender: username, receiver: "admin" },
            { sender: "admin", receiver: username }
          ]
        }).sort({ createdAt: 1 });

        socket.emit('messages:history', messages);
      } catch (error) {
        console.error('Error fetching chat history:', error);
      }
    });

    socket.on('user:typing', ({ sender, receiver }) => {
      io.to(receiver).emit('user:typing', { sender });
    });

    socket.on('user:stopTyping', ({ sender, receiver }) => {
      io.to(receiver).emit('user:stopTyping', { sender });
    });

    // Handle new message
    socket.on('message:send', async (messageData) => {
      try {
        const { sender, receiver, content, file, audio } = messageData;

        // Save message to database
        const newMessage = new Message({
          sender,
          receiver,
          content,
          isRead: false,
          file: file || undefined,
          audio: audio || undefined,
        });

        await newMessage.save();

        // Send to receiver
        io.to(receiver).emit('message:receive', newMessage);

        // Send back to sender for confirmation
        socket.emit('message:sent', newMessage);
      } catch (error) {
        console.error('Error sending message:', error);
        socket.emit('message:error', { error: error.message });
      }
    });

    // Mark messages as read
    socket.on('messages:markRead', async ({ sender, receiver }) => {
      try {
        await Message.updateMany(
          { sender, receiver, isRead: false },
          { isRead: true }
        );

        io.to(sender).emit('messages:updated');
        io.to(receiver).emit('messages:updated');
      } catch (error) {
        console.error('Error marking messages as read:', error);
      }
    });

    socket.on('admin:logout', () => {
      socket.leave('admin');
      adminIsOnline = false;
      broadcastAdminStatus();
      console.log('Admin logged out:', adminIsOnline);
    })

    socket.on('user:logout', async () => {
      // Find the disconnected user and update their status
      for (const [username, data] of activeUsers.entries()) {
        if (data.socketId === socket.id) {
          await User.findByIdAndUpdate(data.userId, {
            isOnline: false,
            lastSeen: Date.now()
          });

          activeUsers.delete(username);

          // Notify admin about user's offline status
          const allUsers = await User.find({}, 'username isOnline lastSeen');
          io.to('admin').emit('admin:userList', allUsers);
          socket.emit('user:logoutSuccess', { message: 'Logged out successfully' });

          break;
        }
      }
    })

    // add code for group creation
    // Create Group Handler
    socket.on('admin:createGroup', async ({ groupName, members }) => {
      console.log('Create group attempt:', groupName, members);
      
      try {
        const isAdminSocket = Array.from(socket.rooms).includes('admin');
        // if (!isAdminSocket) {
        //   socket.emit('admin:groupCreated', {
        //     success: false,
        //     message: 'Unauthorized. Only admin can create groups.'
        //   });
        //   return;
        // }

        // Generate unique group ID
        const groupId = `group_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        // Create new group
        const newGroup = new Group({
          name: groupName,
          groupId,
          members,
          admin: 'admin'
        });

        console.log('New group:', newGroup);
        

        await newGroup.save();

        // Notify all group members
        members.forEach(username => {
          io.to(username).emit('group:created', {
            group: newGroup,
            message: `You've been added to group "${groupName}"`
          });
        });

        // Send success response to admin
        socket.emit('admin:groupCreated', {
          success: true,
          message: 'Group created successfully',
          group: newGroup
        });

        // Send updated group list to admin
        const allGroups = await Group.find({});
        io.to('admin').emit('admin:groupList', allGroups);

      } catch (error) {
        console.error('Create group error:', error);
        socket.emit('admin:groupCreated', {
          success: false,
          message: error.message || 'Failed to create group'
        });
      }
    });

    // Get user's groups
    socket.on('user:getGroups', async (username) => {
      try {
        const userGroups = await Group.find({
          members: username
        }).sort({ lastActivity: -1 });

        socket.emit('user:groupList', userGroups);
      } catch (error) {
        console.error('Get groups error:', error);
      }
    });

    // Send group message
    socket.on('group:sendMessage', async (messageData) => {
      try {
        const { sender, groupId, content, file, audio } = messageData;

        // Verify sender is group member
        const group = await Group.findOne({ groupId });
        if (!group || !group.members.includes(sender)) {
          socket.emit('message:error', { error: 'Not authorized to send messages to this group' });
          return;
        }

        // Save message to database
        const newMessage = new Message({
          sender,
          receiver: groupId, // Use groupId as receiver for group messages
          content,
          isRead: false,
          file: file || undefined,
          audio: audio || undefined,
          isGroupMessage: true
        });

        await newMessage.save();

        // Update group last activity
        await Group.findByIdAndUpdate(group._id, { lastActivity: Date.now() });

        // Send to all group members
        group.members.forEach(member => {
          io.to(member).emit('message:receive', newMessage);
        });

        // Send to admin if not sender
        if (sender !== 'admin') {
          io.to('admin').emit('message:receive', newMessage);
        }

        // Send back to sender for confirmation
        socket.emit('message:sent', newMessage);

      } catch (error) {
        console.error('Error sending group message:', error);
        socket.emit('message:error', { error: error.message });
      }
    });

    // Get group messages
    socket.on('group:getMessages', async (groupId) => {
      try {
        const messages = await Message.find({
          receiver: groupId,
          isGroupMessage: true
        }).sort({ createdAt: 1 });

        socket.emit('messages:history', messages);
      } catch (error) {
        console.error('Error fetching group messages:', error);
      }
    });

    // Leave group
    socket.on('group:leave', async ({ groupId, username }) => {
      try {
        await Group.findOneAndUpdate(
          { groupId },
          { $pull: { members: username } }
        );

        socket.emit('group:left', { groupId, message: 'Left group successfully' });

        // Notify other group members
        const group = await Group.findOne({ groupId });
        if (group) {
          group.members.forEach(member => {
            io.to(member).emit('group:memberLeft', { groupId, username });
          });
        }
      } catch (error) {
        console.error('Leave group error:', error);
      }
    });


    // Handle disconnection
    socket.on('disconnect', async () => {
      console.log('User disconnected:', socket.id);

      // Check if it was the admin who disconnected
      const isAdminSocket = Array.from(socket.rooms).includes('admin');
      if (isAdminSocket) {
        adminIsOnline = false;
        broadcastAdminStatus();
        log('Admin disconnected:', adminIsOnline);
      }

      // Find the disconnected user and update their status
      for (const [username, data] of activeUsers.entries()) {
        if (data.socketId === socket.id) {
          await User.findByIdAndUpdate(data.userId, {
            isOnline: false,
            lastSeen: Date.now()
          });

          activeUsers.delete(username);

          // Notify admin about user's offline status
          const allUsers = await User.find({}, 'username isOnline lastSeen');
          io.to('admin').emit('admin:userList', allUsers);
          socket.emit('user:logoutSuccess', { message: 'Logged out successfully' });


          break;
        }
      }
    });
  });

  return io;
};

module.exports = setupSocket;