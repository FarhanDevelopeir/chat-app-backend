const socketIO = require('socket.io');
const User = require('../models/User');
const Group = require('../models/group');
const Message = require('../models/Message');
const admin = require('../models/admin');
const fetch = require('node-fetch');


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


    // Updated groups fetch handler - REMOVE require statements from inside
    socket.on('groups:fetch', async (data) => {
      try {
        const { username } = data;
        // REMOVED: const Group = require('../models/group');
        // REMOVED: const Message = require('../models/message');

        const userGroups = await Group.find({
          members: username
        }).sort({ createdAt: -1 });

        // Calculate unread message counts for each group
        const groupsWithUnreadCounts = await Promise.all(
          userGroups.map(async (group) => {
            // Count unread messages in this group for this user
            const unreadCount = await Message.countDocuments({
              groupId: group._id,
              sender: { $ne: username }, // Don't count user's own messages
              isRead: false
            });

            // Get the latest message for sorting purposes
            const latestMessage = await Message.findOne({
              groupId: group._id
            }).sort({ createdAt: -1 });

            return {
              ...group.toObject(),
              unreadCount,
              lastMessageTime: latestMessage ? latestMessage.createdAt : group.createdAt
            };
          })
        );

        // Sort by last message time (most recent first)
        groupsWithUnreadCounts.sort((a, b) =>
          new Date(b.lastMessageTime) - new Date(a.lastMessageTime)
        );

        socket.emit('groups:list', groupsWithUnreadCounts);

      } catch (error) {
        console.error('Error fetching groups:', error);
        socket.emit('groups:error', { message: 'Failed to fetch groups' });
      }
    });

    // Updated group join handler - REMOVE require statements
    socket.on('group:join', async (groupId) => {
      try {
        socket.join(groupId);

        const page = 1;
        const limit = 12;
        const skip = (page - 1) * limit;

        // Get total count for pagination
        const totalMessages = await Message.countDocuments({ groupId });

        // Get paginated messages
        const messages = await Message.find({ groupId })
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .then(msgs => msgs.reverse());

        const hasMore = totalMessages > (page * limit);

        socket.emit('messages:history', {
          messages,
          hasMore,
          page,
          total: totalMessages
        });

        // Mark group messages as read for this user
        const username = socket.username;
        if (username) {
          await Message.updateMany(
            {
              groupId,
              isRead: false,
              sender: { $ne: username } // Don't mark own messages as read
            },
            { isRead: true }
          );

          // Emit read status update to all group members
          io.to(groupId).emit('group:readStatusUpdate', {
            groupId,
            readBy: username
          });
        }

      } catch (error) {
        console.error('Error joining group:', error);
      }
    });

    // Updated group send message handler - REMOVE require statements
    socket.on('group:sendMessage', async (data) => {
      try {
        const { content, sender, groupId, file, audio, replyTo } = data;
        // REMOVED: const Group = require('../models/group');

        // Verify user is a member of the group
        const group = await Group.findById(groupId);
        if (!group || !group.members.includes(sender)) {
          socket.emit('group:messageError', { message: 'Access denied' });
          return;
        }

        const newMessage = new Message({
          content,
          sender,
          receiver: null,
          groupId,
          file: file || undefined,
          audio: audio || undefined,
          isRead: false,
          replyTo: replyTo || undefined,
          createdAt: new Date()
        });

        await newMessage.save();

        // Update group's lastActivity timestamp
        await Group.findByIdAndUpdate(groupId, {
          lastActivity: new Date()
        });

        // Emit to all group members
        io.to(groupId).emit('group:messageReceive', newMessage);
        socket.emit('group:messageSent', newMessage);

        // Update groups list for ALL members
        const updateGroupsForAllMembers = async () => {
          for (const member of group.members) {
            const memberSockets = Array.from(io.sockets.sockets.values())
              .filter(s => s.username === member);

            for (const memberSocket of memberSockets) {
              const userGroups = await Group.find({
                members: member
              });

              const groupsWithUnreadCounts = await Promise.all(
                userGroups.map(async (group) => {
                  const unreadCount = await Message.countDocuments({
                    groupId: group._id,
                    sender: { $ne: member },
                    isRead: false
                  });

                  const latestMessage = await Message.findOne({
                    groupId: group._id
                  }).sort({ createdAt: -1 });

                  return {
                    ...group.toObject(),
                    unreadCount,
                    lastMessageTime: latestMessage ? latestMessage.createdAt : group.createdAt
                  };
                })
              );

              groupsWithUnreadCounts.sort((a, b) =>
                new Date(b.lastMessageTime) - new Date(a.lastMessageTime)
              );

              memberSocket.emit('groups:listUpdated', groupsWithUnreadCounts);
            }
          }
        };

        await updateGroupsForAllMembers();


        // // Update latest message for all group members
        // for (const member of group.members) {
        //   io.to(member).emit('user:latestMessageUpdate', {
        //     [groupId]: newMessage
        //   });
        // }

        // Update latest message for all group members
        const messageForBroadcast = {
          content: newMessage.content,
          sender: newMessage.sender,
          createdAt: newMessage.createdAt
        };

        for (const member of group.members) {
          io.to(member).emit('user:latestMessageUpdate', {
            [groupId.toString()]: messageForBroadcast
          });

          // Update unread count for members (except sender)
          if (member !== sender) {
            const unreadCount = await Message.countDocuments({
              groupId: groupId,
              sender: { $ne: member },
              isRead: false
            });

            const updateObj = {};
            updateObj[groupId.toString()] = unreadCount;
            io.to(member).emit('user:unreadCountUpdate', updateObj);
          }
        }

      } catch (error) {
        console.error('Error sending group message:', error);
        socket.emit('group:messageError', { message: 'Failed to send message' });
      }
    });

    // Updated mark read handler - REMOVE require statements
    socket.on('group:markRead', async (data) => {
      try {
        const { groupId, userId } = data;

        const result = await Message.updateMany(
          {
            groupId: groupId,
            sender: { $ne: userId },
            isRead: false
          },
          { isRead: true }
        );

        if (result.modifiedCount > 0) {
          const updatedMessages = await Message.find({
            groupId: groupId,
            isRead: true
          }).sort({ createdAt: 1 });

          io.to(groupId).emit('group:readStatusUpdate', {
            groupId,
            readBy: userId,
            updatedMessages,
            messagesMarkedRead: result.modifiedCount
          });
        }

        // Update the user's groups list
        // REMOVED: const Group = require('../models/group');
        const userGroups = await Group.find({
          members: userId
        });

        const groupsWithUnreadCounts = await Promise.all(
          userGroups.map(async (group) => {
            const unreadCount = await Message.countDocuments({
              groupId: group._id,
              sender: { $ne: userId },
              isRead: false
            });

            const latestMessage = await Message.findOne({
              groupId: group._id
            }).sort({ createdAt: -1 });

            return {
              ...group.toObject(),
              unreadCount,
              lastMessageTime: latestMessage ? latestMessage.createdAt : group.createdAt
            };
          })
        );

        groupsWithUnreadCounts.sort((a, b) =>
          new Date(b.lastMessageTime) - new Date(a.lastMessageTime)
        );

        const userSockets = Array.from(io.sockets.sockets.values())
          .filter(s => s.username === userId);

        userSockets.forEach(userSocket => {
          userSocket.emit('groups:listUpdated', groupsWithUnreadCounts);
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
        user.isPasswordChanged = true
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

    function getUserIP(socket) {
      // Try multiple methods to get the real IP address
      let userIP =
        // Check for forwarded IPs (when behind proxy/load balancer)
        socket.handshake.headers['x-forwarded-for'] ||
        socket.handshake.headers['x-real-ip'] ||
        socket.handshake.headers['x-client-ip'] ||
        socket.handshake.headers['cf-connecting-ip'] || // Cloudflare
        // Fallback to socket IP
        socket.handshake.address ||
        socket.request.connection.remoteAddress ||
        socket.request.socket.remoteAddress ||
        (socket.request.connection.socket ? socket.request.connection.socket.remoteAddress : null);

      // Handle multiple IPs (x-forwarded-for can contain multiple IPs)
      if (userIP && userIP.includes(',')) {
        userIP = userIP.split(',')[0].trim();
      }

      // Clean up IPv6 mapped IPv4 addresses
      if (userIP && userIP.includes('::ffff:')) {
        userIP = userIP.replace('::ffff:', '');
      }

      // Handle localhost cases
      if (userIP === '::1' || userIP === '127.0.0.1') {
        // In development, you might want to use a default or get public IP
        console.log('Local connection detected');
        // You could return a placeholder or try to get public IP
        return 'localhost (' + userIP + ')';
      }

      return userIP || 'unknown';
    }

    const getUserLocation = async (ip) => {
      try {
        if (ip === 'localhost' || ip === 'unknown') {
          ip = '103.53.162.42'; // fallback for dev
        }

        const ipAddress = '103.53.162.42'

        const res = await fetch(`http://ip-api.com/json/${ipAddress}`);
        const data = await res.json();

        if (data.status === 'success') {
          return {
            city: data.city,
            region: data.regionName,
            country: data.country,
            isp: data.isp,
            lat: data.lat,
            lon: data.lon,
          };
        } else {
          return { error: 'Location not found' };
        }
      } catch (err) {
        return { error: 'Error fetching location' };
      }
    };

    

    // User authentication/login
    socket.on('user:login', async ({ username, password, deviceId }) => {
      console.log('User login attempt:', username, password);

      try {


        const userIP = getUserIP(socket);
        // const location = await getUserLocation(userIP);

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
        user.ipAddress = userIP;
        user.isPasswordChanged = false
        await user.save();

        // Store username on socket for group functionality
        socket.username = username;

        // Store user details in the active users map
        activeUsers.set(username, {
          socketId: socket.id,
          userId: user._id,
          ipAddress: userIP
        });

        // Join a room with the username
        socket.join(username);

        // Send user list to admin
        const allUsersRaw = await User.find({}, 'username isOnline lastSeen ipAddress');
        const allUsers = allUsersRaw.map(user => ({
          _id: user._id,
          username: user.username,
          isOnline: user.isOnline,
          lastSeen: user.lastSeen,
          ipAddress: user.ipAddress || 'Not recorded' // Fallback for missing IP
        }));

        io.to('admin').emit('admin:userList', allUsers);
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

        const userIP = getUserIP(socket);
        console.log('User IP:', userIP);
        // Find or create user
        let user = await User.findOne({ username, deviceId });

        // If user doesn't exist
        if (!user) {
          socket.emit('user:loginError', {
            error: 'Invalid username or password'
          });
          return;
        }

        if (user.isPasswordChanged) {
          socket.emit('user:PasswordChangedError', {
            error: 'Your password has been changed, please contact Admin'
          });
          return;
        }

        user.isOnline = true;
        user.lastSeen = Date.now();
        user.ipAddress = userIP;
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
        const allUsers = await User.find({}, 'username isOnline lastSeen ipAddress');
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
        const page = 1;
        const limit = 12;
        const skip = (page - 1) * limit;

        // Get total count for pagination
        const totalMessages = await Message.countDocuments({
          $or: [
            { sender: username, receiver: "admin" },
            { sender: "admin", receiver: username }
          ]
        });

        // Get paginated messages (most recent first, then reverse for chronological order)
        const messages = await Message.find({
          $or: [
            { sender: username, receiver: "admin" },
            { sender: "admin", receiver: username }
          ]
        })
          .sort({ createdAt: -1 }) // Get newest first
          .skip(skip)
          .limit(limit)
          .then(msgs => msgs.reverse()); // Reverse to show chronological order

        const hasMore = totalMessages > (page * limit);

        socket.emit('messages:history', {
          messages,
          hasMore,
          page,
          total: totalMessages
        });

        // Mark messages from this user as read
        await Message.updateMany(
          { sender: username, receiver: 'admin', isRead: false },
          { isRead: true }
        );

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
      User.find({}, 'username isOnline lastSeen profilePicture ipAddress')
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
          User.find({}, 'username isOnline lastSeen profilePicture ipAddress')
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

    // for realtime reading of messages

    // Updated admin:selectUser handler
    socket.on('admin:selectUser', async (username) => {
      try {
        const page = 1;
        const limit = 12;
        const skip = (page - 1) * limit;

        // Get total count for pagination
        const totalMessages = await Message.countDocuments({
          $or: [
            { sender: username, receiver: "admin" },
            { sender: "admin", receiver: username }
          ]
        });

        // Get paginated messages
        const messages = await Message.find({
          $or: [
            { sender: username, receiver: "admin" },
            { sender: "admin", receiver: username }
          ]
        })
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .then(msgs => msgs.reverse());

        const hasMore = totalMessages > (page * limit);

        socket.emit('messages:history', {
          messages,
          hasMore,
          page,
          total: totalMessages
        });

        // Mark messages from this user as read
        const updatedMessages = await Message.updateMany(
          { sender: username, receiver: 'admin', isRead: false },
          { isRead: true }
        );

        // If messages were marked as read, notify the sender
        if (updatedMessages.modifiedCount > 0) {
          const readMessages = await Message.find({
            sender: username,
            receiver: 'admin',
            isRead: true
          }).sort({ createdAt: 1 });

          io.to(username).emit('messages:readStatusUpdate', readMessages);
        }

      } catch (error) {
        console.error('Error fetching chat history:', error);
      }
    });

    // New handler for loading more messages
    socket.on('messages:loadMore', async (data) => {
      try {
        const { page = 1, limit = 12, sender, receiver, groupId } = data;
        const skip = (page - 1) * limit;

        let query;
        let totalMessages;

        if (groupId) {
          // Group chat
          query = { groupId };
          totalMessages = await Message.countDocuments(query);
        } else {
          // Direct chat
          query = {
            $or: [
              { sender: sender, receiver: receiver },
              { sender: receiver, receiver: sender }
            ]
          };
          totalMessages = await Message.countDocuments(query);
        }

        // Get paginated messages
        const messages = await Message.find(query)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .then(msgs => msgs.reverse());

        const hasMore = totalMessages > (page * limit);

        socket.emit('messages:history', {
          messages,
          hasMore,
          page,
          total: totalMessages
        });

      } catch (error) {
        console.error('Error loading more messages:', error);
        socket.emit('messages:loadError', { error: error.message });
      }
    });

    // Handle new message (Modified to send unread count updates)
    socket.on('message:send', async (messageData) => {
      try {
        const { sender, receiver, content, file, audio, replyTo } = messageData;

        // Save message to database
        const newMessage = new Message({
          sender,
          receiver,
          content,
          isRead: false,
          file: file || undefined,
          audio: audio || undefined,
          replyTo: replyTo || undefined, // Add this line
        });

        await newMessage.save();

        // Send to receiver
        io.to(receiver).emit('message:receive', newMessage);

        // Send back to sender for confirmation
        socket.emit('message:sent', newMessage);

        // // If message is sent to admin, update unread count
        // if (receiver === 'admin') {
        //   const unreadCount = await Message.countDocuments({
        //     sender: sender,
        //     receiver: 'admin',
        //     isRead: false
        //   });

        //   // Send unread count update to all admin sockets
        //   io.to('admin').emit('admin:unreadCountUpdate', { username: sender, count: unreadCount });


        // }

        // show unread message length 

        // Update latest message for both users
        const messageForBroadcast = {
          content: newMessage.content,
          sender: newMessage.sender,
          createdAt: newMessage.createdAt
        };

        // Update latest message for receiver
        if (receiver === 'admin') {
          io.to(receiver).emit('user:latestMessageUpdate', {
            [sender]: messageForBroadcast
          });
          // Update for sender
          io.to(sender).emit('user:latestMessageUpdate', {
            'admin': messageForBroadcast
          });
        } else {
          io.to(receiver).emit('user:latestMessageUpdate', {
            'admin': messageForBroadcast
          });
          io.to(sender).emit('user:latestMessageUpdate', {
            [receiver]: messageForBroadcast
          });
        }

        // Update unread count for receiver
        if (receiver !== sender) {
          if (receiver === 'admin') {
            // Admin receiving message - update admin's unread count
            const adminUnreadCount = await Message.countDocuments({
              sender: sender,
              receiver: 'admin',
              isRead: false
            });
            io.to('admin').emit('admin:unreadCountUpdate', { username: sender, count: adminUnreadCount });
          } else {
            // User receiving message from admin - update user's unread count
            const userUnreadCount = await Message.countDocuments({
              sender: 'admin',
              receiver: receiver,
              isRead: false
            });
            io.to(receiver).emit('user:unreadCountUpdate', { 'admin': userUnreadCount });
          }
        }


        //  close unread messages length

      } catch (error) {
        console.error('Error sending message:', error);
        socket.emit('message:error', { error: error.message });
      }
    });

    // Mark messages as read (Modified to send read status updates to sender)
    socket.on('messages:markRead', async ({ sender, receiver }) => {
      try {
        const result = await Message.updateMany(
          { sender, receiver, isRead: false },
          { isRead: true }
        );

        // If messages were actually updated (marked as read)
        if (result.modifiedCount > 0) {
          // Get the updated messages that were just marked as read
          const updatedMessages = await Message.find({
            sender,
            receiver,
            isRead: true
          }).sort({ createdAt: 1 });

          // Notify the original sender that their messages have been read
          io.to(sender).emit('messages:readStatusUpdate', updatedMessages);
        }

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

    // Handle emoji reactions
    socket.on('message:addEmojiReaction', async (data) => {
      try {
        const { messageId, emoji, username } = data;

        const message = await Message.findById(messageId);
        if (!message) {
          socket.emit('message:error', { error: 'Message not found' });
          return;
        }

        // Initialize reactions if not exists
        if (!message.reactions) {
          message.reactions = new Map();
        }

        // Get current users who reacted with this emoji
        const currentUsers = message.reactions.get(emoji) || [];

        // Toggle user's reaction
        let updatedUsers;
        if (currentUsers.includes(username)) {
          // Remove user's reaction
          updatedUsers = currentUsers.filter(user => user !== username);
          if (updatedUsers.length === 0) {
            message.reactions.delete(emoji);
          } else {
            message.reactions.set(emoji, updatedUsers);
          }
        } else {
          // Add user's reaction
          updatedUsers = [...currentUsers, username];
          message.reactions.set(emoji, updatedUsers);
        }

        await message.save();

        // Convert Map to Object for transmission
        const reactionsObj = {};
        for (let [key, value] of message.reactions.entries()) {
          reactionsObj[key] = value;
        }

        // Broadcast reaction update to both sender and receiver
        io.to(message.sender).emit('message:emojiReactionUpdate', {
          messageId: messageId,
          reactions: reactionsObj
        });

        io.to(message.receiver).emit('message:emojiReactionUpdate', {
          messageId: messageId,
          reactions: reactionsObj
        });

      } catch (error) {
        console.error('Error handling emoji reaction:', error);
        socket.emit('message:error', { error: error.message });
      }
    });

    // Handle message deletion
    socket.on('message:delete', async (data) => {
      try {
        const { messageId, deletedBy, isAdmin } = data;

        const message = await Message.findById(messageId);
        if (!message) {
          socket.emit('message:error', { error: 'Message not found' });
          return;
        }

        // Check if user has permission to delete
        const canDelete = (message.sender === deletedBy) || isAdmin;

        if (!canDelete) {
          socket.emit('message:error', { error: 'Permission denied' });
          return;
        }

        // Mark message as deleted instead of actually deleting it
        message.isDeleted = true;
        message.deletedBy = deletedBy;
        message.deletedAt = new Date();

        // Clear sensitive content but keep metadata
        const originalContent = message.content;
        message.content = isAdmin
          ? "This message was deleted by admin"
          : `This message was deleted by ${deletedBy}`;

        // Remove file and audio references
        if (message.file) {
          message.file = undefined;
        }
        if (message.audio) {
          message.audio = undefined;
        }

        await message.save();

        // Broadcast deletion to both participants
        const deletionData = {
          messageId: messageId,
          deletedBy: deletedBy,
          isAdmin: isAdmin
        };

        io.to(message.sender).emit('message:deleted', deletionData);
        io.to(message.receiver).emit('message:deleted', deletionData);

        console.log(`Message ${messageId} deleted by ${deletedBy}${isAdmin ? ' (admin)' : ''}`);

      } catch (error) {
        console.error('Error deleting message:', error);
        socket.emit('message:error', { error: error.message });
      }
    });

    // Updated message history handler to include reactions
    socket.on('messages:getHistory', async ({ sender, receiver }) => {
      try {
        const messages = await Message.find({
          $or: [
            { sender: sender, receiver: receiver },
            { sender: receiver, receiver: sender }
          ]
        }).sort({ createdAt: 1 });

        // Convert reactions Map to Object for each message
        const messagesWithReactions = messages.map(msg => {
          const messageObj = msg.toObject();
          if (messageObj.reactions) {
            const reactionsObj = {};
            for (let [key, value] of msg.reactions.entries()) {
              reactionsObj[key] = value;
            }
            messageObj.reactions = reactionsObj;
          }
          return messageObj;
        });

        socket.emit('messages:history', messagesWithReactions);
      } catch (error) {
        console.error('Error fetching message history:', error);
        socket.emit('message:error', { error: error.message });
      }
    });
    // close for realtime reading of messages

    // When admin connects, join admin room for broadcast updates
    socket.on('admin:login', (adminData) => {
      socket.join('admin');
      // ... rest of your admin login logic
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

    // show unread messages length
    socket.on('user:getUnreadCounts', async (data) => {
      try {
        console.log('Getting unread counts for:', data.username);
        const { username } = data;
        const unreadCounts = {};

        // Get admin chat unread count
        const adminUnreadCount = await Message.countDocuments({
          sender: 'admin',
          receiver: username,
          isRead: false
        });
        console.log('Admin unread count:', adminUnreadCount);

        if (adminUnreadCount > 0) {
          unreadCounts['admin'] = adminUnreadCount;
        }

        // Get group unread counts
        const userGroups = await Group.find({ members: username });
        for (const group of userGroups) {
          const groupUnreadCount = await Message.countDocuments({
            groupId: group._id,
            sender: { $ne: username },
            isRead: false
          });
          console.log(`Group ${group.name} unread count:`, groupUnreadCount);

          if (groupUnreadCount > 0) {
            unreadCounts[group._id.toString()] = groupUnreadCount;
          }
        }

        console.log('Sending unread counts:', unreadCounts);
        socket.emit('user:unreadCounts', unreadCounts);

      } catch (error) {
        console.error('Error getting unread counts:', error);
      }
    });

    // Get latest messages for user
    socket.on('user:getLatestMessages', async (data) => {
      try {
        console.log('Getting latest messages for:', data.username);
        const { username } = data;
        const latestMessages = {};

        // Get latest admin message
        const latestAdminMessage = await Message.findOne({
          $or: [
            { sender: 'admin', receiver: username },
            { sender: username, receiver: 'admin' }
          ]
        }).sort({ createdAt: -1 });

        if (latestAdminMessage) {
          latestMessages['admin'] = {
            content: latestAdminMessage.content,
            sender: latestAdminMessage.sender,
            createdAt: latestAdminMessage.createdAt
          };
        }

        // Get latest group messages
        const userGroups = await Group.find({ members: username });
        for (const group of userGroups) {
          const latestGroupMessage = await Message.findOne({
            groupId: group._id
          }).sort({ createdAt: -1 });

          if (latestGroupMessage) {
            latestMessages[group._id.toString()] = {
              content: latestGroupMessage.content,
              sender: latestGroupMessage.sender,
              createdAt: latestGroupMessage.createdAt
            };
          }
        }

        console.log('Sending latest messages:', latestMessages);
        socket.emit('user:latestMessages', latestMessages);

      } catch (error) {
        console.error('Error getting latest messages:', error);
      }
    });

    // Get latest messages for user
    socket.on('admin:getLatestMessages', async (data) => {
      try {
        console.log('Getting latest messages for:', data.username);
        const { username } = data;
        const latestMessages = {};

        if (username === 'admin') {
          // If admin is requesting, get latest messages with all users
          console.log('Admin requesting messages - getting all user conversations');

          // Get all unique users who have exchanged messages with admin
          const adminMessages = await Message.find({
            $or: [
              { sender: 'admin' },
              { receiver: 'admin' }
            ]
          }).select('sender receiver');

          // Extract unique usernames (excluding admin)
          const uniqueUsers = new Set();
          adminMessages.forEach(msg => {
            if (msg.sender !== 'admin') uniqueUsers.add(msg.sender);
            if (msg.receiver !== 'admin') uniqueUsers.add(msg.receiver);
          });

          // Get latest message for each user
          for (const user of uniqueUsers) {
            const latestUserMessage = await Message.findOne({
              $or: [
                { sender: 'admin', receiver: user },
                { sender: user, receiver: 'admin' }
              ]
            }).sort({ createdAt: -1 });

            if (latestUserMessage) {
              latestMessages[user] = {
                content: latestUserMessage.content,
                sender: latestUserMessage.sender,
                createdAt: latestUserMessage.createdAt
              };
            }
          }

          // Also get latest group messages for admin
          const adminGroups = await Group.find({ members: 'admin' });
          for (const group of adminGroups) {
            const latestGroupMessage = await Message.findOne({
              groupId: group._id
            }).sort({ createdAt: -1 });

            if (latestGroupMessage) {
              latestMessages[group._id.toString()] = {
                content: latestGroupMessage.content,
                sender: latestGroupMessage.sender,
                createdAt: latestGroupMessage.createdAt,
                groupName: group.name // Optional: include group name for admin
              };
            }
          }

        }


        console.log('Sending latest messages:', latestMessages);
        socket.emit('admin:latestMessages', latestMessages);

      } catch (error) {
        console.error('Error getting latest messages:', error);
      }
    });


    // Mark chat as read - NEW HANDLER
    socket.on('user:markChatAsRead', async (data) => {
      try {
        const { username, chatId, chatType } = data;
        console.log('Marking chat as read:', { username, chatId, chatType });

        if (chatType === 'admin') {
          // Mark admin messages as read
          const result = await Message.updateMany(
            { sender: 'admin', receiver: username, isRead: false },
            { isRead: true }
          );
          console.log('Marked admin messages as read:', result.modifiedCount);

          // Send updated unread count (should be 0)
          socket.emit('user:unreadCountUpdate', { 'admin': 0 });

        } else if (chatType === 'group') {
          // Mark group messages as read
          const result = await Message.updateMany(
            { groupId: chatId, sender: { $ne: username }, isRead: false },
            { isRead: true }
          );
          console.log('Marked group messages as read:', result.modifiedCount);

          // Send updated unread count (should be 0)
          const updateObj = {};
          updateObj[chatId] = 0;
          socket.emit('user:unreadCountUpdate', updateObj);
        }

      } catch (error) {
        console.error('Error marking chat as read:', error);
      }
    });



    // Update unread count
    socket.on('user:updateUnreadCount', async (data) => {
      try {
        const { username, chatId, increment, reset } = data;

        if (reset) {
          // Mark messages as read
          if (chatId === 'admin') {
            await Message.updateMany(
              { sender: 'admin', receiver: username, isRead: false },
              { isRead: true }
            );
          } else {
            await Message.updateMany(
              { groupId: chatId, sender: { $ne: username }, isRead: false },
              { isRead: true }
            );
          }
        }

        // Get updated unread count
        let unreadCount = 0;
        if (chatId === 'admin') {
          unreadCount = await Message.countDocuments({
            sender: 'admin',
            receiver: username,
            isRead: false
          });
        } else {
          unreadCount = await Message.countDocuments({
            groupId: chatId,
            sender: { $ne: username },
            isRead: false
          });
        }

        socket.emit('user:unreadCountUpdate', { [chatId]: unreadCount });
      } catch (error) {
        console.error('Error updating unread count:', error);
      }
    });

    // close unread messages length


    // Add these socket event handlers in your backend

// Pin message for direct chat
socket.on('message:pin', async (data) => {
  try {
    const { messageId, sender, receiver, pinnedBy } = data;
    
    // First unpin any existing pinned message in this chat
    await Message.updateMany(
      {
        $or: [
          { sender: sender, receiver: receiver },
          { sender: receiver, receiver: sender }
        ],
        isPinned: true
      },
      { 
        isPinned: false, 
        pinnedBy: null,
        pinnedAt: null 
      }
    );

    // Pin the new message
    const pinnedMessage = await Message.findByIdAndUpdate(
      messageId,
      { 
        isPinned: true, 
        pinnedBy: pinnedBy,
        pinnedAt: new Date()
      },
      { new: true }
    );

    if (pinnedMessage) {
      // Emit to both sender and receiver
      io.to(sender).emit('message:pinned', { message: pinnedMessage });
      io.to(receiver).emit('message:pinned', { message: pinnedMessage });
    }

  } catch (error) {
    console.error('Error pinning message:', error);
    socket.emit('message:error', { error: 'Failed to pin message' });
  }
});

// Unpin message for direct chat
socket.on('message:unpin', async (data) => {
  try {
    const { messageId, sender, receiver } = data;
    
    const unpinnedMessage = await Message.findByIdAndUpdate(
      messageId,
      { 
        isPinned: false, 
        pinnedBy: null,
        pinnedAt: null 
      },
      { new: true }
    );

    if (unpinnedMessage) {
      // Emit to both sender and receiver
      io.to(sender).emit('message:unpinned', { messageId });
      io.to(receiver).emit('message:unpinned', { messageId });
    }

  } catch (error) {
    console.error('Error unpinning message:', error);
    socket.emit('message:error', { error: 'Failed to unpin message' });
  }
});

// Get pinned message for direct chat
socket.on('message:getPinnedMessage', async (data) => {
  try {
    const { sender, receiver } = data;
    
    const pinnedMessage = await Message.findOne({
      $or: [
        { sender: sender, receiver: receiver },
        { sender: receiver, receiver: sender }
      ],
      isPinned: true
    });

    if (pinnedMessage) {
      socket.emit('message:pinned', { message: pinnedMessage });
    }

  } catch (error) {
    console.error('Error getting pinned message:', error);
  }
});

// Pin message for group chat
socket.on('group:pinMessage', async (data) => {
  try {
    const { messageId, groupId, pinnedBy } = data;
    
    // Verify user is a member of the group
    const group = await Group.findById(groupId);
    if (!group || !group.members.includes(pinnedBy)) {
      socket.emit('group:error', { message: 'Access denied' });
      return;
    }

    // Unpin any existing pinned message in this group
    await Message.updateMany(
      { groupId: groupId, isPinned: true },
      { 
        isPinned: false, 
        pinnedBy: null,
        pinnedAt: null 
      }
    );

    // Pin the new message
    const pinnedMessage = await Message.findByIdAndUpdate(
      messageId,
      { 
        isPinned: true, 
        pinnedBy: pinnedBy,
        pinnedAt: new Date()
      },
      { new: true }
    );

    if (pinnedMessage) {
      // Emit to all group members
      io.to(groupId).emit('group:messagePinned', { message: pinnedMessage });
    }

  } catch (error) {
    console.error('Error pinning group message:', error);
    socket.emit('group:error', { error: 'Failed to pin message' });
  }
});

// Unpin message for group chat
socket.on('group:unpinMessage', async (data) => {
  try {
    const { messageId, groupId, unpinnedBy } = data;
    
    // Verify user is a member of the group
    const group = await Group.findById(groupId);
    if (!group || !group.members.includes(unpinnedBy)) {
      socket.emit('group:error', { message: 'Access denied' });
      return;
    }

    const unpinnedMessage = await Message.findByIdAndUpdate(
      messageId,
      { 
        isPinned: false, 
        pinnedBy: null,
        pinnedAt: null 
      },
      { new: true }
    );

    if (unpinnedMessage) {
      // Emit to all group members
      io.to(groupId).emit('group:messageUnpinned', { messageId });
    }

  } catch (error) {
    console.error('Error unpinning group message:', error);
    socket.emit('group:error', { error: 'Failed to unpin message' });
  }
});

// Get pinned message for group chat
socket.on('group:getPinnedMessage', async (data) => {
  try {
    const { groupId } = data;
    
    const pinnedMessage = await Message.findOne({
      groupId: groupId,
      isPinned: true
    });

    if (pinnedMessage) {
      socket.emit('group:messagePinned', { message: pinnedMessage });
    }

  } catch (error) {
    console.error('Error getting pinned group message:', error);
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