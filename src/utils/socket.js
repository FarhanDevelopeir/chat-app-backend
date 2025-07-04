const socketIO = require('socket.io');
const User = require('../models/User');
const Group = require('../models/group');
const Message = require('../models/Message');
const admin = require('../models/admin');
const fetch = require('node-fetch');
const { default: mongoose } = require('mongoose');
const { filterNonSubAdmins, filterUsersForSubAdmin } = require('./utils');
const Announcement = require('../models/Announcement');
// const filterUsersForSubAdmin = require('./utils');


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

    console.log("Full Socket Object:", socket);
    

    // Store username on socket for group functionality
    socket.username = null;

    // ========== GROUP MANAGEMENT HANDLERS (NEW) ==========


    const broadcastUserListUpdate = async (io) => {
      try {
        const users = await User.find({}, 'username isOnline lastSeen profilePicture ipAddress isSubAdmin');
        io.to('admin').emit('admin:userList', filterNonSubAdmins(users));
      } catch (error) {
        console.error('Error broadcasting user list update:', error);
      }
    };

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



    // ========== USER HANDLERS (NEW) ==========


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
        // const allUsersRaw = await User.find({}, 'username isOnline lastSeen profilePicture ipAddress isSubAdmin');
        // const filteredUsers = filterNonSubAdmins(allUsersRaw);
        // io.to('admin').emit('admin:userList', filteredUsers);

        broadcastUserListUpdate(io)

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
        // const allUsers = await User.find({}, 'username isOnline lastSeen profilePicture ipAddress isSubAdmin');
        // const filteredUsers = filterNonSubAdmins(allUsers);
        // io.to('admin').emit('admin:userList', filteredUsers);

        broadcastUserListUpdate(io)

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

    socket.on('user:subadminChat', async (data) => {
      try {
        const { username, subAdminUsername } = data;
        console.log('User subAdmin chat:', { username, subAdminUsername });

        const page = 1;
        const limit = 12;
        const skip = (page - 1) * limit;

        // Get total count for pagination
        const totalMessages = await Message.countDocuments({
          $or: [
            { sender: username, receiver: subAdminUsername },
            { sender: subAdminUsername, receiver: username }
          ]
        });

        // Get paginated messages (most recent first, then reverse for chronological order)
        const messages = await Message.find({
          $or: [
            { sender: username, receiver: subAdminUsername },
            { sender: subAdminUsername, receiver: username }
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

        // Mark messages from subAdmin to this user as read
        await Message.updateMany(
          { sender: subAdminUsername, receiver: username, isRead: false },
          { isRead: true }
        );

      } catch (error) {
        console.error('Error fetching subAdmin chat history:', error);
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



        console.log('Profile updated successfully for user:', username);

      } catch (error) {
        console.error('Profile update error:', error);
        socket.emit('user:profileUpdateError', { error: error.message });
      }
    });

    // User typing indicators
    socket.on('user:typing', ({ sender, receiver }) => {
      io.to(receiver).emit('user:typing', { sender });
    });

    socket.on('user:stopTyping', ({ sender, receiver }) => {
      io.to(receiver).emit('user:stopTyping', { sender });
    });

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
          // const allUsers = await User.find({}, 'username isOnline lastSeen profilePicture ipAddress isSubAdmin');
          // const filteredUsers = filterNonSubAdmins(allUsers);
          // io.to('admin').emit('admin:userList', filteredUsers);


          broadcastUserListUpdate(io)

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

        // Get subAdmin chat unread counts
        const subAdmins = await User.find({
          isSubAdmin: true,
          username: { $ne: username }
        }).select('username');

        for (const subAdmin of subAdmins) {
          const subAdminUnreadCount = await Message.countDocuments({
            sender: subAdmin.username,
            receiver: username,
            isRead: false
          });
          console.log(`SubAdmin ${subAdmin.username} unread count:`, subAdminUnreadCount);

          if (subAdminUnreadCount > 0) {
            unreadCounts[subAdmin.username] = subAdminUnreadCount;
          }
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

        // Check if this is a subAdmin
        const isSubAdmin = await User.findOne({ username, isSubAdmin: true });

        if (username === 'admin' || isSubAdmin) {
          // For admin or subadmin, get all conversations
          const targetUser = username === 'admin' ? 'admin' : username;

          // Get all unique users who have exchanged messages
          const userMessages = await Message.find({
            $or: [
              { sender: targetUser },
              { receiver: targetUser }
            ]
          }).select('sender receiver');

          const uniqueUsers = new Set();
          userMessages.forEach(msg => {
            if (msg.sender !== targetUser) uniqueUsers.add(msg.sender);
            if (msg.receiver !== targetUser) uniqueUsers.add(msg.receiver);
          });

          // Get latest message for each user
          for (const user of uniqueUsers) {
            const latestUserMessage = await Message.findOne({
              $or: [
                { sender: targetUser, receiver: user },
                { sender: user, receiver: targetUser }
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

          // Get latest group messages
          const userGroups = await Group.find({ members: targetUser });
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

          const eventName = isSubAdmin ? 'subadmin:latestMessages' : 'admin:latestMessages';
          console.log(`Sending latest messages via ${eventName}:`, latestMessages);
          socket.emit(eventName, latestMessages);
        } else {
          // Regular user logic
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

          const subAdmins = await User.find({
            isSubAdmin: true,
            username: { $ne: username }
          }).select('username');

          console.log('subAdmins in users chat', subAdmins)

          for (const subAdmin of subAdmins) {
            const latestSubAdminMessage = await Message.findOne({
              $or: [
                { sender: subAdmin.username, receiver: username },
                { sender: username, receiver: subAdmin.username }
              ]
            }).sort({ createdAt: -1 });

            if (latestSubAdminMessage) {
              latestMessages[subAdmin.username] = {
                content: latestSubAdminMessage.content,
                sender: latestSubAdminMessage.sender,
                createdAt: latestSubAdminMessage.createdAt
              };
            }

            console.log('latestSubAdminMessage in users chat', latestSubAdminMessage)
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

          console.log('Sending user latest messages:', latestMessages);
          socket.emit('user:latestMessages', latestMessages);
        }

      } catch (error) {
        console.error('Error getting latest messages:', error);
      }
    });

    socket.on('user:getSubAdmins', async (data) => {
      try {
        const { username } = data;
        console.log('Getting subAdmins for user:', username);

        // Find all users who are subAdmins
        const subAdmins = await User.find({
          isSubAdmin: true,
          assignedUsers: { $in: [username] },
          username: { $ne: username } // Exclude the requesting user if they are also a subAdmin
        }).select('username profilePicture isOnline');

        console.log('Found subAdmins:', subAdmins);
        socket.emit('user:subAdminsList', subAdmins);

      } catch (error) {
        console.error('Error getting subAdmins:', error);
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

          if (result.modifiedCount > 0) {
            const readMessages = await Message.find({
              sender: 'admin',
              receiver: username,
              isRead: true
            }).sort({ createdAt: 1 });

            io.to('admin').emit('messages:readStatusUpdate', readMessages);
          }

          // Send updated unread count (should be 0)
          socket.emit('user:unreadCountUpdate', { 'admin': 0 });

        } else if (chatType === 'subadmin') {
          // Mark subAdmin messages as read
          const result = await Message.updateMany(
            { sender: chatId, receiver: username, isRead: false },
            { isRead: true }
          );
          console.log('Marked subAdmin messages as read:', result.modifiedCount);

          if (result.modifiedCount > 0) {
            const readMessages = await Message.find({
              sender: chatId,
              receiver: username,
              isRead: true
            }).sort({ createdAt: 1 });

            io.to(chatId).emit('messages:readStatusUpdate', readMessages);
          }

          // Send updated unread count (should be 0)
          const updateObj = {};
          updateObj[chatId] = 0;
          socket.emit('user:unreadCountUpdate', updateObj);

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
          // Reset (mark as read)
          if (chatId === 'admin') {
            await Message.updateMany(
              { sender: 'admin', receiver: username, isRead: false },
              { isRead: true }
            );
          } else if (mongoose.Types.ObjectId.isValid(chatId)) {
            // Check if it's a group message
            const groupExists = await Group.findOne({ _id: chatId });

            if (groupExists) {
              await Message.updateMany(
                { groupId: chatId, sender: { $ne: username }, isRead: false },
                { isRead: true }
              );
            } else {
              // Fallback: treat as a direct message (in case it's not a valid group)
              await Message.updateMany(
                { sender: chatId, receiver: username, isRead: false },
                { isRead: true }
              );
            }
          } else {
            // It's a direct 1-on-1 message (e.g., from subAdmin)
            await Message.updateMany(
              { sender: chatId, receiver: username, isRead: false },
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
        } else if (mongoose.Types.ObjectId.isValid(chatId)) {
          // Check if it's a group
          const groupExists = await Group.findOne({ _id: chatId });

          if (groupExists) {
            unreadCount = await Message.countDocuments({
              groupId: chatId,
              sender: { $ne: username },
              isRead: false
            });
          } else {
            // fallback to 1-on-1 chat using sender/receiver
            unreadCount = await Message.countDocuments({
              sender: chatId,
              receiver: username,
              isRead: false
            });
          }
        } else {
          // Direct message from subAdmin or other user (chatId is a username)
          unreadCount = await Message.countDocuments({
            sender: chatId,
            receiver: username,
            isRead: false
          });
        }

        socket.emit('user:unreadCountUpdate', { [chatId]: unreadCount });
      } catch (error) {
        console.error('Error updating unread count:', error);
      }
    });


    // ========== ADMIN HANDLERS (NEW) ==========


    socket.on('admin:createUser', async (data) => {
      try {


        const { username, password, isSubAdmin, assignedUsers } = data;

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


        if (isSubAdmin && (!assignedUsers || assignedUsers.length === 0)) {
          socket.emit('admin:userCreated', {
            success: false,
            message: 'Sub admin must have at least one assigned user'
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

        // Validate assigned users exist (if sub admin)
        if (isSubAdmin && assignedUsers) {
          const existingUsers = await User.find({
            username: { $in: assignedUsers },
            isSubAdmin: false
          });

          if (existingUsers.length !== assignedUsers.length) {
            socket.emit('admin:userCreated', {
              success: false,
              message: 'Some assigned users do not exist or are sub admins'
            });
            return;
          }
        }

        if (!user) {
          user = new User({
            username,
            password,
            isOnline: false,
            isSubAdmin,
            assignedUsers: isSubAdmin ? assignedUsers : []
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


        broadcastUserListUpdate(io)

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

        // Find the user by original UserID
        let user = await User.findOne({ _id: userID });

        // **NEW: Only notify the specific user to reload their page**
        io.emit('user:forceReload', {
          targetUsername: username,
          reason: 'Password updated by admin'
        });

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
        // const allUsers = await User.find({}, 'username isOnline lastSeen profilePicture ipAddress isSubAdmin');
        // const filteredUsers = filterNonSubAdmins(allUsers);
        // io.to('admin').emit('admin:userList', filteredUsers);

        broadcastUserListUpdate(io)

      } catch (error) {
        console.error('Update user error:', error);
        socket.emit('admin:userUpdated', {
          success: false,
          message: error.message || 'Failed to update user'
        });
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

      // // Send user list to admin
      // User.find({}, 'username isOnline lastSeen profilePicture ipAddress isSubAdmin')
      //   .then(users => {
      //     const filteredUsers = filterNonSubAdmins(users);
      //     socket.emit('admin:userList', filteredUsers);
      //   })
      //   .catch(error => {
      //     console.error('Error fetching users:', error);
      //   });

      broadcastUserListUpdate(io)



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
        if (username === 'admin') {
          // Main admin login
          const Admin = await admin.findOne({ username });

          if (!Admin) {
            return socket.emit('admin:loginFailure', { error: 'Admin not found' });
          }

          const isMatch = await Admin.comparePassword(password);
          if (!isMatch) {
            return socket.emit('admin:loginFailure', { error: 'Invalid password' });
          }

          console.log('✅ Admin authenticated:', username);
          socket.username = 'admin';
          adminIsOnline = true;
          socket.emit('admin:loginSuccess');
          broadcastAdminStatus();
          socket.emit('admin:profiledata', Admin);

          // const users = await User.find({}, 'username isOnline lastSeen profilePicture ipAddress isSubAdmin');
          // const filteredUsers = filterNonSubAdmins(users);
          // socket.emit('admin:userList', filteredUsers);

          broadcastUserListUpdate(io)

          // Send admin groups
          const Group = require('../models/group');
          const groups = await Group.find({ members: 'admin' }).sort({ createdAt: -1 });
          socket.emit('groups:list', groups);

          return;
        }

        // Not admin, check if it's a subadmin in User collection
        let subAdmin = await User.findOne({ username });

        if (!subAdmin) {
          return socket.emit('subadmin:loginError', { error: 'Invalid username or password' });
        }

        const isPasswordValid = await subAdmin.comparePassword(password);
        if (!isPasswordValid) {
          return socket.emit('subadmin:loginError', { error: 'Invalid username or password' });
        }

        if (!subAdmin.isSubAdmin) {
          return socket.emit('subadmin:loginError', { error: 'You are not allowed to access this panel' });
        }

        subAdmin.isOnline = true
        await subAdmin.save()

        // Valid subadmin
        socket.username = username;
        socket.join(username);
        socket.emit('subadmin:loginSuccess');
        socket.emit('subadmin:profiledata', subAdmin);

        // Send list of users to subadmin
        const users = await User.find({}, 'username isOnline lastSeen profilePicture ipAddress isSubAdmin assignedUsers');
        const filteredUsers = filterUsersForSubAdmin(users, username);
        socket.emit('subadmin:userList', filteredUsers);

        // Send groups the subadmin is part of
        const Group = require('../models/group');
        const groups = await Group.find({ members: username }).sort({ createdAt: -1 });
        socket.emit('groups:list', groups);

      } catch (err) {
        console.error('Error during login:', err);
        socket.emit('admin:loginFailure', { error: 'Unexpected error during login' });
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

    // Updated admin:selectUser handler
    socket.on('admin:selectUser', async (username) => {
      try {
        const page = 1;
        const limit = 12;
        const skip = (page - 1) * limit;


        let query, totalMessages, messages;

        if (username === 'broadcast') {

          // Count total broadcast messages from current user role
          const uniqueBroadcastMessages = await Message.aggregate([
            {
              $match: {
                sender: 'admin',
                isBroadcast: true
              }
            },
            {
              $addFields: {
                createdAtTruncated: {
                  $dateTrunc: {
                    date: "$createdAt",
                    unit: "second"
                  }
                }
              }
            },
            {
              $group: {
                _id: {
                  content: "$content",
                  createdAt: "$createdAtTruncated"
                },
                doc: { $first: "$$ROOT" }
              }
            },
            {
              $replaceRoot: {
                newRoot: "$doc"
              }
            },
            {
              $sort: {
                createdAt: -1
              }
            }
          ]);



          // Count total unique broadcast messages
          totalMessages = uniqueBroadcastMessages.length;

          // Get paginated broadcast messages from current user role
          messages = uniqueBroadcastMessages
            .slice(skip, skip + limit)
            .reverse();

        } else {
          // Regular chat logic (existing code)
          // Get total count for pagination
          totalMessages = await Message.countDocuments({
            $or: [
              { sender: username, receiver: "admin" },
              { sender: "admin", receiver: username }
            ]
          });

          // Get paginated messages
          messages = await Message.find({
            $or: [
              { sender: username, receiver: "admin" },
              { sender: "admin", receiver: username }
            ]
          })
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .then(msgs => msgs.reverse());
        }

        const hasMore = totalMessages > (page * limit);

        socket.emit('messages:history', {
          messages,
          hasMore,
          page,
          total: totalMessages
        });

        if (username !== 'broadcast') {
          // Mark messages from this user as read
          const updatedMessages = await Message.updateMany(
            { sender: username, receiver: 'admin', isRead: false },
            { isRead: true }
          );

          if (updatedMessages.modifiedCount > 0) {
            const readMessages = await Message.find({
              sender: username,
              receiver: 'admin',
              isRead: true
            }).sort({ createdAt: 1 });

            io.to(username).emit('messages:readStatusUpdate', readMessages);
          }
        }
      } catch (error) {
        console.error('Error fetching chat history:', error);
      }
    });


    socket.on('admin:logout', () => {
      socket.leave('admin');
      adminIsOnline = false;
      broadcastAdminStatus();
      console.log('Admin logged out:', adminIsOnline);
    })

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
                groupName: group.name
              };
            }
          }
        } else {
          // Check if this is a subAdmin requesting messages
          const isSubAdmin = await User.findOne({ username, isSubAdmin: true });
          if (isSubAdmin) {
            console.log('SubAdmin requesting messages - getting all user conversations for:', username);

            // Get all unique users who have exchanged messages with this subadmin
            const subAdminMessages = await Message.find({
              $or: [
                { sender: username },
                { receiver: username }
              ]
            }).select('sender receiver');

            // Extract unique usernames (excluding the subadmin)
            const uniqueUsers = new Set();
            subAdminMessages.forEach(msg => {
              if (msg.sender !== username) uniqueUsers.add(msg.sender);
              if (msg.receiver !== username) uniqueUsers.add(msg.receiver);
            });

            // Get latest message for each user
            for (const user of uniqueUsers) {
              const latestUserMessage = await Message.findOne({
                $or: [
                  { sender: username, receiver: user },
                  { sender: user, receiver: username }
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

            // Also get latest group messages for subadmin
            const subAdminGroups = await Group.find({ members: username });
            for (const group of subAdminGroups) {
              const latestGroupMessage = await Message.findOne({
                groupId: group._id
              }).sort({ createdAt: -1 });

              if (latestGroupMessage) {
                latestMessages[group._id.toString()] = {
                  content: latestGroupMessage.content,
                  sender: latestGroupMessage.sender,
                  createdAt: latestGroupMessage.createdAt,
                  groupName: group.name
                };
              }
            }

            console.log('Sending subadmin latest messages:', latestMessages);
            socket.emit('subadmin:latestMessages', latestMessages);
            return;
          }
        }

        console.log('Sending latest messages:', latestMessages);
        socket.emit('admin:latestMessages', latestMessages);

      } catch (error) {
        console.error('Error getting latest messages:', error);
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

    socket.on('subadmin:isLogin', async ({ username }) => {
      socket.join(username);
      socket.username = username;
      socket.emit('subadmin:loginSuccess');

      try {
        let subAdmin = await User.findOne({ username, isSubAdmin: true });

        if (!subAdmin) {
          return;
        }

        subAdmin.isOnline = true
        await subAdmin.save()

        socket.emit('subadmin:profiledata', subAdmin);

      } catch (error) {
        console.error('subadmin not found:', error);
      }

      const users = await User.find({}, 'username isOnline lastSeen profilePicture ipAddress isSubAdmin assignedUsers');
      const filteredUsers = filterUsersForSubAdmin(users, username);
      socket.emit('subadmin:userList', filteredUsers);

      // Send groups the subadmin is part of
      const Group = require('../models/group');
      const groups = await Group.find({ members: username }).sort({ createdAt: -1 });
      socket.emit('groups:list', groups);
    });

    socket.on('subadmin:updateProfile', async ({ username, profilePicture }) => {

      try {
        // Find and update user
        let subAdmin = await User.findOne({ username, isSubAdmin: true });
        if (subAdmin) {
          subAdmin.profilePicture = profilePicture;
          await subAdmin.save();
        }

        if (!subAdmin) {
          socket.emit('subadmin:profileUpdateError', {
            error: 'User not found'
          });
          return;
        }

        // Emit updated user data back to the user
        socket.emit('subadmin:profileUpdated', subAdmin);

        // Optionally, broadcast to admin or other users if needed
        // io.to('admin').emit('user:profileUpdated', user);

        console.log('Profile updated successfully for user:', username);

      } catch (error) {
        console.error('Profile update error:', error);
        socket.emit('subadmin:profileUpdateError', { error: error.message });
      }
    });

    socket.on('subadmin:logout', async (username) => {
      let subAdmin = await User.findOne({ username, isSubAdmin: true });

      if (!subAdmin) {
        return;
      }

      subAdmin.isOnline = false
      await subAdmin.save()

      socket.emit('user:getSubAdmins', { username });
    })


    socket.on('subadmin:getUnreadCounts', async (data) => {
      try {
        const { username } = data;

        console.log('username subadmin unread count', username)

        // Get all users who have sent messages to this subadmin
        const users = await Message.distinct('sender', { receiver: username });

        const unreadCounts = {};

        console.log('users of subadmin unread count', users)

        // Count unread messages for each user
        for (const senderUsername of users) {
          if (senderUsername !== username) { // Exclude subadmin's own messages
            const count = await Message.countDocuments({
              sender: senderUsername,
              receiver: username,
              isRead: false
            });
            unreadCounts[senderUsername] = count;
          }
        }

        socket.emit('subadmin:unreadCounts', unreadCounts);
      } catch (error) {
        console.error('Error getting subadmin unread counts:', error);
      }
    });

    socket.on('subadmin:selectUser', async ({ sender, receiver }) => {
      try {
        const page = 1;
        const limit = 12;
        const skip = (page - 1) * limit;

        let query, totalMessages, messages;


        if (receiver === 'broadcast') {

          // Count total broadcast messages from current user role
          const uniqueBroadcastMessages = await Message.aggregate([
            {
              $match: {
                sender: sender,
                isBroadcast: true
              }
            },
            {
              $addFields: {
                createdAtTruncated: {
                  $dateTrunc: {
                    date: "$createdAt",
                    unit: "second"
                  }
                }
              }
            },
            {
              $group: {
                _id: {
                  content: "$content",
                  createdAt: "$createdAtTruncated"
                },
                doc: { $first: "$$ROOT" }
              }
            },
            {
              $replaceRoot: {
                newRoot: "$doc"
              }
            },
            {
              $sort: {
                createdAt: -1
              }
            }
          ]);

          // Count total unique broadcast messages
          totalMessages = uniqueBroadcastMessages.length;

          // Get paginated broadcast messages from current user role
          messages = uniqueBroadcastMessages
            .slice(skip, skip + limit)
            .reverse();

        } else {

          // Get total count for pagination
          totalMessages = await Message.countDocuments({
            $or: [
              { sender: sender, receiver: receiver },
              { sender: receiver, receiver: sender }
            ]
          });

          // Get paginated messages
          messages = await Message.find({
            $or: [
              { sender: sender, receiver: receiver },
              { sender: receiver, receiver: sender }
            ]
          })
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .then(msgs => msgs.reverse());

        }

        const hasMore = totalMessages > (page * limit);

        socket.emit('messages:history', {
          messages,
          hasMore,
          page,
          total: totalMessages
        });

        if (receiver !== 'broadcast') {

          // Mark messages from this user as read
          const updatedMessages = await Message.updateMany(
            { sender: sender, receiver: receiver, isRead: false },
            { isRead: true }
          );

          // If messages were marked as read, notify the sender
          if (updatedMessages.modifiedCount > 0) {
            const readMessages = await Message.find({
              sender: sender,
              receiver: receiver,
              isRead: true
            }).sort({ createdAt: 1 });

            io.to(receiver).emit('messages:readStatusUpdate', readMessages);
          }
        }
      } catch (error) {
        console.error('Error fetching chat history:', error);
      }
    });



    // ========== MESSAGES HANDLERS (NEW) ==========


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
          replyTo: replyTo || undefined,
        });

        await newMessage.save();

        // Send to receiver
        io.to(receiver).emit('message:receive', newMessage);

        // Send back to sender for confirmation
        socket.emit('message:sent', newMessage);

        // Update latest message for both users
        const messageForBroadcast = {
          content: newMessage.content,
          sender: newMessage.sender,
          createdAt: newMessage.createdAt
        };

        const receiverIsSubAdmin = await User.findOne({ username: receiver, isSubAdmin: true });
        const senderIsSubAdmin = await User.findOne({ username: sender, isSubAdmin: true });

        // Emit latest message updates
        if (receiver === 'admin') {
          io.to(receiver).emit('user:latestMessageUpdate', {
            [sender]: messageForBroadcast
          });
          io.to(sender).emit('user:latestMessageUpdate', {
            'admin': messageForBroadcast
          });
        } else if (receiverIsSubAdmin) {
          // Receiver is subadmin
          io.to(receiver).emit('user:latestMessageUpdate', {
            [sender]: messageForBroadcast
          });
          io.to(sender).emit('user:latestMessageUpdate', {
            [receiver]: messageForBroadcast
          });
        } else if (senderIsSubAdmin) {
          // Receiver is subadmin
          io.to(receiver).emit('user:latestMessageUpdate', {
            [sender]: messageForBroadcast
          });
          io.to(sender).emit('user:latestMessageUpdate', {
            [receiver]: messageForBroadcast
          });
        } else {
          // Receiver is a normal user
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
            // Check if receiver is a subAdmin
            const isSubAdmin = await User.findOne({ username: receiver, isSubAdmin: true });
            const senderIsSubAdmin = await User.findOne({ username: sender, isSubAdmin: true });
            if (isSubAdmin) {
              // SubAdmin receiving message - update subAdmin's unread count
              const subAdminUnreadCount = await Message.countDocuments({
                sender: sender,
                receiver: receiver,
                isRead: false
              });
              io.to(receiver).emit('subadmin:unreadCountUpdate', { username: sender, count: subAdminUnreadCount });
            } else if (senderIsSubAdmin) {
              // User receiving message from subAdmin - update user's unread count
              const userUnreadCount = await Message.countDocuments({
                sender: sender,
                receiver: receiver,
                isRead: false
              });
              io.to(receiver).emit('user:unreadCountUpdate', { [sender]: userUnreadCount });
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
        }

      } catch (error) {
        console.error('Error sending message:', error);
        socket.emit('message:error', { error: error.message });
      }
    });


    socket.on('messages:markRead', async ({ sender, receiver, chatType = null, isAdmin, isSubAdmin }) => {
      try {
        // const result = await Message.updateMany(
        //   { sender, receiver, isRead: false },
        //   { isRead: true }
        // );

        console.log('chatType here in server ', chatType)
        console.log('isSubAdmin here in server', isSubAdmin)

        let updateQuery = { receiver, isRead: false };

        // Apply chatType condition for sender filtering
        if (isAdmin || isSubAdmin) {
          updateQuery.sender = sender
        } else {
          if (chatType === 'user') {
            updateQuery.sender = 'admin';
          } else if (chatType === null) {
            updateQuery.sender = sender;
          } else {
            updateQuery.sender = { $ne: 'admin' };
          }
        }


        const result = await Message.updateMany(
          updateQuery,
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
        } else {
          // Check if receiver is a subAdmin
          const isSubAdmin = await User.findOne({ username: receiver, isSubAdmin: true });
          if (isSubAdmin) {
            const unreadCount = await Message.countDocuments({
              sender: sender,
              receiver: receiver,
              isRead: false
            });
            io.to(receiver).emit('subadmin:unreadCountUpdate', { username: sender, count: unreadCount });
          }
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
        const { messageId, deletedBy, isAdmin, isSubAdmin } = data;

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


    // Pin message for subadmin-user chat
    socket.on('subadmin:pinMessage', async (data) => {
      try {
        const { messageId, sender, receiver, pinnedBy } = data;

        // Verify that one of them is a subadmin
        const senderUser = await User.findOne({ username: sender });
        const receiverUser = await User.findOne({ username: receiver });

        if (!senderUser || !receiverUser ||
          !(senderUser.isSubAdmin || receiverUser.isSubAdmin)) {
          socket.emit('subadmin:error', { message: 'Access denied - SubAdmin required' });
          return;
        }

        // First unpin any existing pinned message in this subadmin-user chat
        await Message.updateMany(
          {
            $or: [
              { sender: sender, receiver: receiver },
              { sender: receiver, receiver: sender }
            ],
            isPinned: true,
            groupId: null // Ensure it's not a group message
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
          io.to(sender).emit('subadmin:messagePinned', { message: pinnedMessage });
          io.to(receiver).emit('subadmin:messagePinned', { message: pinnedMessage });
        }

      } catch (error) {
        console.error('Error pinning subadmin message:', error);
        socket.emit('subadmin:error', { error: 'Failed to pin message' });
      }
    });

    // Unpin message for subadmin-user chat
    socket.on('subadmin:unpinMessage', async (data) => {
      try {
        const { messageId, sender, receiver, unpinnedBy } = data;

        // Verify that one of them is a subadmin
        const senderUser = await User.findOne({ username: sender });
        const receiverUser = await User.findOne({ username: receiver });

        if (!senderUser || !receiverUser ||
          !(senderUser.isSubAdmin || receiverUser.isSubAdmin)) {
          socket.emit('subadmin:error', { message: 'Access denied - SubAdmin required' });
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
          // Emit to both sender and receiver
          io.to(sender).emit('subadmin:messageUnpinned', { messageId });
          io.to(receiver).emit('subadmin:messageUnpinned', { messageId });
        }

      } catch (error) {
        console.error('Error unpinning subadmin message:', error);
        socket.emit('subadmin:error', { error: 'Failed to unpin message' });
      }
    });

    // Get pinned message for subadmin-user chat
    socket.on('chat:getPinnedChats', async (data) => {
      try {
        const { userType, currentUsername } = data;
        let currentUser;

        // Get the appropriate user based on type
        if (userType === 'admin') {
          currentUser = await admin.findOne({ username: 'admin' }); // or however you identify admin
        } else if (userType === 'subadmin') {
          currentUser = await User.findOne({
            username: currentUsername,
            isSubAdmin: true
          });
        }

        if (currentUser) {
          const pinnedChats = currentUser.getPinnedChats();
          const eventPrefix = userType === 'admin' ? 'admin' : 'subadmin';
          socket.emit(`${eventPrefix}:pinnedChats`, { pinnedChats });
        }
      } catch (error) {
        console.error('Error getting pinned chats:', error);
      }
    });

    socket.on('chat:togglePin', async (data) => {
      try {
        const { targetUsername, userType, currentUsername } = data;
        let currentUser;

        // Get the appropriate user based on type
        if (userType === 'admin') {
          currentUser = await admin.findOne({ username: 'admin' }); // or however you identify admin
        } else if (userType === 'subadmin') {
          currentUser = await User.findOne({
            username: currentUsername,
            isSubAdmin: true
          });
        }

        if (!currentUser) {
          socket.emit('error', { message: 'User not found' });
          return;
        }

        const isPinned = currentUser.togglePinChat(targetUsername);
        await currentUser.save();

        // Emit to the specific admin/subadmin
        const eventPrefix = userType === 'admin' ? 'admin' : 'subadmin';
        socket.emit(`${eventPrefix}:chatPinToggled`, {
          targetUsername,
          isPinned,
          pinnedChats: currentUser?.getPinnedChats()
        });

      } catch (error) {
        console.error('Error toggling pin:', error);
        socket.emit('error', { message: 'Failed to toggle pin' });
      }
    });

    socket.on('message:broadcast', async (messageData) => {
      try {
        const { sender, content, replyTo, file, audio } = messageData;

        // Get all regular users (exclude admin and subadmins)


        let targetUsers = [];

        if (sender === 'admin') {
          // Admin: get all regular users (non-subadmins)
          targetUsers = await User.find({ isSubAdmin: false }).select('username');
        } else {
          const senderUser = await User.findOne({ username: sender, isSubAdmin: true });

          if (!senderUser) {
            throw new Error('Sender not found');
          }
          // SubAdmin: send to assigned users
          targetUsers = await User.find({
            username: { $in: senderUser.assignedUsers },
            isSubAdmin: false
          }).select('username');
        }

        // Create and save a message for each user
        const broadcastMessages = [];

        for (const user of targetUsers) {
          const newMessage = new Message({
            sender,
            receiver: user.username,
            content,
            isRead: false,
            isBroadcast: true, // NEW: Add broadcast flag
            replyTo: replyTo || undefined,
            file: file || undefined,
            audio: audio || undefined,
          });

          const savedMessage = await newMessage.save();
          broadcastMessages.push(savedMessage);

          // Send to each user
          io.to(user.username).emit('message:receive', savedMessage);
          // socket.emit('message:sent', savedMessage);

          // Update unread count for each user
          const userUnreadCount = await Message.countDocuments({
            sender: sender,
            receiver: user.username,
            isRead: false
          });

          if (sender === 'admin') {
            io.to(user.username).emit('user:unreadCountUpdate', {
              'admin': userUnreadCount
            });
          } else {
            // SubAdmin broadcast
            io.to(user.username).emit('user:unreadCountUpdate', {
              [sender]: userUnreadCount
            });
          }

          // Update latest message
          const messageForBroadcast = {
            content: savedMessage.content,
            sender: savedMessage.sender,
            createdAt: savedMessage.createdAt,
            isBroadcast: true
          };

          if (sender === 'admin') {
            io.to(user.username).emit('user:latestMessageUpdate', {
              'admin': messageForBroadcast
            });
          } else {
            // SubAdmin broadcast
            io.to(user.username).emit('user:latestMessageUpdate', {
              [sender]: messageForBroadcast
            });
          }
        }

        // Send confirmation back to sender
        socket.emit('message:broadcastSent', {
          success: true,
          messageCount: broadcastMessages.length,
          content: content
        });



        // Update admin/subadmin's latest messages for each user
        for (const user of targetUsers) {
          const messageForBroadcast = {
            content: content,
            sender: sender,
            createdAt: new Date(),
            isBroadcast: true
          };

          io.to(sender).emit('user:latestMessageUpdate', {
            [user.username]: messageForBroadcast
          });
        }

      } catch (error) {
        console.error('Error sending broadcast message:', error);
        socket.emit('message:error', { error: error.message });
      }
    });



    // Add these socket handlers to your backend socket file

    // Create Announcement
    socket.on('announcement:create', async (data) => {
      try {
        const { text, createdBy, userType } = data;

        // Verify admin/subadmin permission
        const isAdminSocket = Array.from(socket.rooms).includes('admin');
        const user = await User.findOne({ username: createdBy });

        if (!isAdminSocket && !user?.isSubAdmin) {
          socket.emit('error', { message: 'Unauthorized' });
          return;
        }

        // Create announcement in database
        const announcement = new Announcement({
          text,
          createdBy,
          createdAt: new Date(),
          isActive: true
        });

        await announcement.save();

        // Broadcast to all users
        io.emit('user:newAnnouncement', announcement);

        // Send back to creator
        const eventName = user?.isSubAdmin ? 'announcement:created' : 'announcement:created';
        socket.emit(eventName, announcement);

      } catch (error) {
        console.error('Error creating announcement:', error);
        socket.emit('error', { message: 'Failed to create announcement' });
      }
    });

    // Fetch Announcements for Admin/SubAdmin
    socket.on('announcements:fetch', async (data) => {
      try {
        const { userType } = data;

        const announcements = await Announcement.find({ isActive: true })
          .sort({ createdAt: -1 })
          .limit(10);

        socket.emit('announcements:list', announcements);

      } catch (error) {
        console.error('Error fetching announcements:', error);
      }
    });

    // Delete Announcement
    socket.on('announcement:delete', async (data) => {
      try {
        const { announcementId, userType } = data;

        // Verify admin/subadmin permission
        const isAdminSocket = Array.from(socket.rooms).includes('admin');
        const currentUser = await User.findOne({ username: socket.username });

        if (!isAdminSocket && !currentUser?.isSubAdmin) {
          socket.emit('error', { message: 'Unauthorized' });
          return;
        }

        // Delete announcement
        await Announcement.findByIdAndUpdate(announcementId, { isActive: false });

        // Broadcast deletion to all users
        io.emit('user:announcementDeleted', announcementId);

        // Confirm deletion to admin/subadmin
        socket.emit('announcement:deleted', announcementId);

      } catch (error) {
        console.error('Error deleting announcement:', error);
        socket.emit('error', { message: 'Failed to delete announcement' });
      }
    });

    // Get Announcements for Regular Users
    socket.on('user:getAnnouncements', async (data) => {
      try {
        const { username } = data;

        const announcements = await Announcement.find({ isActive: true })
          .sort({ createdAt: -1 })
          .limit(5);

        socket.emit('user:announcements', announcements);

      } catch (error) {
        console.error('Error getting user announcements:', error);
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
          // const allUsers = await User.find({}, 'username isOnline lastSeen profilePicture ipAddress isSubAdmin');
          // const filteredUsers = filterNonSubAdmins(allUsers);
          // io.to('admin').emit('admin:userList', filteredUsers);

          broadcastUserListUpdate(io)


          break;
        }
      }
    });
  });

  console.log("activeUsers", activeUsers);
  

  return io;
};

module.exports = setupSocket;