const socketIO = require('socket.io');
const User = require('../models/User');
const Message = require('../models/Message');
const admin = require('../models/admin');

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

    // Store username on socket for group functionality
    socket.username = null;

    // ========== GROUP MANAGEMENT HANDLERS (NEW) ==========

    // Create a new group
    socket.on('group:create', async (data) => {
      try {
        const { name, members, createdBy } = data;

        // Verify admin permissions
        const isAdminSocket = Array.from(socket.rooms).includes('admin');
        if (!isAdminSocket) {
          socket.emit('group:createError', { message: 'Unauthorized. Only admin can create groups.' });
          return;
        }

        // Add admin/creator to members if not already included
        const allMembers = [...new Set([...members, createdBy])];

        // Create group in database (you'll need to create Group model)
        const Group = require('../models/group'); // You'll need to create this model

        const newGroup = new Group({
          name,
          members: allMembers,
          createdBy
        });

        await newGroup.save();

        // Emit to all group members that a new group was created
        allMembers.forEach(member => {
          const memberSockets = Array.from(io.sockets.sockets.values())
            .filter(s => s.username === member);

          memberSockets.forEach(memberSocket => {
            memberSocket.emit('group:created', {
              group: newGroup,
              message: `You've been added to group "${name}"`
            });
          });

        });

        socket.emit('group:createSuccess', { group: newGroup });

      } catch (error) {
        console.error('Error creating group:', error);
        socket.emit('group:createError', { message: 'Failed to create group' });
      }
    });

    socket.on('group:update', async (data) => {
      try {
        const { name, members, createdBy, groupId } = data;

        const Group = require('../models/group');
        const group = await Group.findById(groupId);

        if (!group) {
          return socket.emit('group:updated', { success: false, message: 'Group not found' });
        }

        const oldMembers = group.members;
        group.name = name;
        group.members = [...new Set([...members, createdBy])];
        await group.save();

        const allAffectedUsers = new Set([...oldMembers, ...group.members]);

        // Notify members
        allAffectedUsers.forEach(member => {
          const memberSockets = Array.from(io.sockets.sockets.values())
            .filter(s => s.username === member);

          memberSockets.forEach(memberSocket => {
            memberSocket.emit('group:updated', {
              group: group,
              message: `Group has been updated`
            });
          });
        });

      } catch (err) {
        console.error(err);
        socket.emit('group:updated', { success: false, message: 'Error updating group' });
      }
    });


    // Get user's groups
    socket.on('groups:fetch', async (data) => {
      try {
        const { username } = data;
        const Group = require('../models/group');

        const userGroups = await Group.find({
          members: username
        }).sort({ createdAt: -1 });


        socket.emit('groups:list', userGroups);

      } catch (error) {
        console.error('Error fetching groups:', error);
        socket.emit('groups:error', { message: 'Failed to fetch groups' });
      }
    });

    // Join a group room
    socket.on('group:join', async (groupId) => {
      try {
        const Group = require('../models/group');
        const group = await Group.findById(groupId);

        if (!group || !group.members.includes(socket.username)) {
          socket.emit('group:joinError', { message: 'Access denied' });
          return;
        }

        socket.join(groupId);

        // Send group message history
        const messages = await Message.find({
          groupId: groupId
        }).sort({ createdAt: 1 }).limit(100);

        socket.emit('messages:history', messages);

      } catch (error) {
        console.error('Error joining group:', error);
        socket.emit('group:joinError', { message: 'Failed to join group' });
      }
    });

    // Send group message
    socket.on('group:sendMessage', async (data) => {
      try {
        const { content, sender, groupId, file, audio } = data;
        const Group = require('../models/group');

        // Verify user is a member of the group
        const group = await Group.findById(groupId);
        if (!group || !group.members.includes(sender)) {
          socket.emit('group:messageError', { message: 'Access denied' });
          return;
        }

        const newMessage = new Message({
          content,
          sender,
          receiver: null, // null for group messages
          groupId,
          file: file || undefined,
          audio: audio || undefined,
          isRead: false
        });

        await newMessage.save();

        // Emit to all group members
        io.to(groupId).emit('group:messageReceive', newMessage);

        // Also emit back to sender for confirmation
        socket.emit('group:messageSent', newMessage);

      } catch (error) {
        console.error('Error sending group message:', error);
        socket.emit('group:messageError', { message: 'Failed to send message' });
      }
    });

    // Mark group messages as read
    socket.on('group:markRead', async (data) => {
      try {
        const { groupId, userId } = data;

        await Message.updateMany(
          {
            groupId: groupId,
            sender: { $ne: userId },
            isRead: false
          },
          { isRead: true }
        );

        // Emit read status to all group members
        io.to(groupId).emit('group:messagesRead', {
          groupId,
          readBy: userId
        });

      } catch (error) {
        console.error('Error marking group messages as read:', error);
      }
    });

    // Group typing indicators
    socket.on('group:typing', (data) => {
      const { groupId, sender } = data;
      socket.to(groupId).emit('group:userTyping', { sender });
    });

    socket.on('group:stopTyping', (data) => {
      const { groupId, sender } = data;
      socket.to(groupId).emit('group:userStoppedTyping', { sender });
    });

    // ========== EXISTING HANDLERS (UNCHANGED) ==========

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

        // Store username on socket for group functionality
        socket.username = username;

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

        try {
          const Admin = await admin.findOne({ username: 'admin' });

          if (!Admin) {
            return;
          }

          socket.emit('admin:profiledata', Admin);

        } catch (error) {
          console.error('Admin not found:', error);
        }

        // Send previous messages to the user
        const messages = await Message.find({
          $or: [
            { sender: username, receiver: "admin" },
            { sender: "admin", receiver: username }
          ]
        }).sort({ createdAt: 1 });

        socket.emit('messages:history', messages);

        // Send user's groups
        try {
          const Group = require('../models/group');
          const userGroups = await Group.find({
            members: username
          }).sort({ createdAt: -1 });

          socket.emit('groups:list', userGroups);
        } catch (error) {
          console.error('Error fetching user groups:', error);
        }

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

        user.isOnline = true;
        user.lastSeen = Date.now();
        await user.save();

        // Store username on socket for group functionality
        socket.username = username;

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

        try {
          const Admin = await admin.findOne({ username: 'admin' });

          if (!Admin) {
            return;
          }

          socket.emit('admin:profiledata', Admin);

        } catch (error) {
          console.error('Admin not found:', error);
        }

        // Send previous messages to the user
        const messages = await Message.find({
          $or: [
            { sender: username, receiver: "admin" },
            { sender: "admin", receiver: username }
          ]
        }).sort({ createdAt: 1 });

        socket.emit('messages:history', messages);

        // Send user's groups
        try {
          const Group = require('../models/group');
          const userGroups = await Group.find({
            members: username
          }).sort({ createdAt: -1 });

          socket.emit('groups:list', userGroups);
        } catch (error) {
          console.error('Error fetching user groups:', error);
        }

      } catch (error) {
        console.error('Login error:', error);
        socket.emit('user:loginError', { error: error.message });
      }
    });

    socket.on('user:adminChat', async (username) => {
      try {
        // Get chat history with the selected user
        const messages = await Message.find({
          $or: [
            { sender: username, receiver: "admin" },
            { sender: "admin", receiver: username }
          ]
        }).sort({ createdAt: 1 });

        socket.emit('messages:history', messages);

        // Mark messages from this user as read
        await Message.updateMany(
          { sender: username, receiver: 'admin', isRead: false },
          { isRead: true }
        );

        // Send updated unread count for this specific user
        // const unreadCount = await Message.countDocuments({
        //   sender: username,
        //   receiver: 'admin',
        //   isRead: false
        // });

        // socket.emit('admin:unreadCountUpdate', { username, count: unreadCount });

      } catch (error) {
        console.error('Error fetching chat history:', error);
      }
    });

    socket.on('user:updateProfile', async ({ username, profilePicture }) => {
      console.log('User profile update attempt:', username, profilePicture ? 'with image' : 'image removed');

      try {
        // Find and update user
        const user = await User.findOneAndUpdate(
          { username },
          { profilePicture },
          { new: true }
        );

        if (!user) {
          socket.emit('user:profileUpdateError', {
            error: 'User not found'
          });
          return;
        }

        // Emit updated user data back to the user
        socket.emit('user:profileUpdated', user);

        // Optionally, broadcast to admin or other users if needed
        // io.to('admin').emit('user:profileUpdated', user);

        console.log('Profile updated successfully for user:', username);

      } catch (error) {
        console.error('Profile update error:', error);
        socket.emit('user:profileUpdateError', { error: error.message });
      }
    });

    socket.on('admin:updateProfile', async ({ username, profilePicture }) => {

      try {
        // Find and update user
        const Admin = await admin.findOneAndUpdate(
          { username },
          { profilePicture },
          { new: true }
        );

        if (!Admin) {
          socket.emit('admin:profileUpdateError', {
            error: 'User not found'
          });
          return;
        }

        // Emit updated user data back to the user
        socket.emit('admin:profileUpdated', Admin);

        // Optionally, broadcast to admin or other users if needed
        // io.to('admin').emit('user:profileUpdated', user);

        console.log('Profile updated successfully for user:', username);

      } catch (error) {
        console.error('Profile update error:', error);
        socket.emit('admin:profileUpdateError', { error: error.message });
      }
    });

    // Admin authentication
    socket.on('admin:login', async () => {
      socket.join('admin');
      socket.username = 'admin'; // Set admin username
      adminIsOnline = true;
      socket.emit('admin:loginSuccess');
      broadcastAdminStatus();

      try {
        const Admin = await admin.findOne({ username: 'admin' });

        if (!Admin) {
          return;
        }

        socket.emit('admin:profiledata', Admin);

      } catch (error) {
        console.error('Admin not found:', error);
      }

      // Send user list to admin
      User.find({}, 'username isOnline lastSeen profilePicture')
        .then(users => {
          socket.emit('admin:userList', users);
        })
        .catch(error => {
          console.error('Error fetching users:', error);
        });



      // Send admin's groups
      try {
        const Group = require('../models/group');
        Group.find({
          members: 'admin'
        }).sort({ createdAt: -1 })
          .then(groups => {
            socket.emit('groups:list', groups);
          })
          .catch(error => {
            console.error('Error fetching admin groups:', error);
          });
      } catch (error) {
        console.error('Error with admin groups:', error);
      }
    });

    socket.on('admin:loginAttempt', async ({ username, password }) => {
      try {
        const Admin = await admin.findOne({ username });

        if (!Admin) {
          return;
        }

        const isMatch = await Admin.comparePassword(password);

        if (isMatch) {
          console.log('✅ Admin authenticated:', username);
          socket.username = 'admin'; // Set admin username
          adminIsOnline = true;
          socket.emit('admin:loginSuccess');
          broadcastAdminStatus();

          socket.emit('admin:profiledata', Admin);

          // Send user list to admin
          User.find({}, 'username isOnline lastSeen profilePicture')
            .then(users => {
              socket.emit('admin:userList', users);
            })
            .catch(error => {
              console.error('Error fetching users:', error);
            });

          // Send admin's groups
          try {
            const Group = require('../models/group');
            Group.find({
              members: 'admin'
            }).sort({ createdAt: -1 })
              .then(groups => {
                socket.emit('groups:list', groups);
              })
              .catch(error => {
                console.error('Error fetching admin groups:', error);
              });
          } catch (error) {
            console.error('Error with admin groups:', error);
          }

        } else {
          console.log('❌ Admin password incorrect');
          socket.emit('admin:loginFailure');
        }

      } catch (err) {
        console.error('Error during admin login:', err);
        socket.emit('admin:loginFailure');
      }
    });

    // Get unread message counts for admin
    socket.on('admin:getUnreadCounts', async () => {
      try {
        // Get all users who have sent messages to admin
        const users = await Message.distinct('sender', { receiver: 'admin' });

        const unreadCounts = {};

        // Count unread messages for each user
        for (const username of users) {
          if (username !== 'admin') { // Exclude admin's own messages
            const count = await Message.countDocuments({
              sender: username,
              receiver: 'admin',
              isRead: false
            });
            unreadCounts[username] = count;
          }
        }

        socket.emit('admin:unreadCounts', unreadCounts);
      } catch (error) {
        console.error('Error getting unread counts:', error);
      }
    });

    // Admin selects a user to chat with (Modified)
    socket.on('admin:selectUser', async (username) => {
      try {
        // Get chat history with the selected user
        const messages = await Message.find({
          $or: [
            { sender: username, receiver: "admin" },
            { sender: "admin", receiver: username }
          ]
        }).sort({ createdAt: 1 });

        // console.log('messages of selected user', messages)

        socket.emit('messages:history', messages);

        // Mark messages from this user as read
        await Message.updateMany(
          { sender: username, receiver: 'admin', isRead: false },
          { isRead: true }
        );

        // Send updated unread count for this specific user
        const unreadCount = await Message.countDocuments({
          sender: username,
          receiver: 'admin',
          isRead: false
        });

        socket.emit('admin:unreadCountUpdate', { username, count: unreadCount });

      } catch (error) {
        console.error('Error fetching chat history:', error);
      }
    });

    // Handle new message (Modified to send unread count updates)
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

        // If message is sent to admin, update unread count
        if (receiver === 'admin') {
          const unreadCount = await Message.countDocuments({
            sender: sender,
            receiver: 'admin',
            isRead: false
          });

          // Send unread count update to all admin sockets
          io.to('admin').emit('admin:unreadCountUpdate', { username: sender, count: unreadCount });
        }

      } catch (error) {
        console.error('Error sending message:', error);
        socket.emit('message:error', { error: error.message });
      }
    });

    // Mark messages as read (Modified to send unread count updates)
    socket.on('messages:markRead', async ({ sender, receiver }) => {
      try {
        await Message.updateMany(
          { sender, receiver, isRead: false },
          { isRead: true }
        );

        // If admin is marking messages as read
        if (receiver === 'admin') {
          const unreadCount = await Message.countDocuments({
            sender: sender,
            receiver: 'admin',
            isRead: false
          });

          // Send updated unread count
          io.to('admin').emit('admin:unreadCountUpdate', { username: sender, count: unreadCount });
        }

        io.to(sender).emit('messages:updated');
        io.to(receiver).emit('messages:updated');
      } catch (error) {
        console.error('Error marking messages as read:', error);
      }
    });

    // Optional: Get total unread count across all users
    socket.on('admin:getTotalUnreadCount', async () => {
      try {
        const totalUnread = await Message.countDocuments({
          receiver: 'admin',
          isRead: false
        });

        socket.emit('admin:totalUnreadCount', totalUnread);
      } catch (error) {
        console.error('Error getting total unread count:', error);
      }
    });

    // User typing indicators
    socket.on('user:typing', ({ sender, receiver }) => {
      io.to(receiver).emit('user:typing', { sender });
    });

    socket.on('user:stopTyping', ({ sender, receiver }) => {
      io.to(receiver).emit('user:stopTyping', { sender });
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

    // Handle disconnection
    socket.on('disconnect', async () => {
      console.log('User disconnected:', socket.id);

      // Check if it was the admin who disconnected
      const isAdminSocket = Array.from(socket.rooms).includes('admin');
      if (isAdminSocket) {
        adminIsOnline = false;
        broadcastAdminStatus();
        console.log('Admin disconnected:', adminIsOnline);
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

          break;
        }
      }
    });
  });

  return io;
};

module.exports = setupSocket;