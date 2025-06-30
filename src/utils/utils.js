function filterNonSubAdmins(users) {
  return users.filter(user => !user.isSubAdmin);
}


function filterUsersForSubAdmin(users, subAdminUsername) {
  // Find the sub-admin user to get their assigned users
  const subAdmin = users.find(user => user.username === subAdminUsername && user.isSubAdmin);

  if (!subAdmin || !subAdmin.assignedUsers) {
    return [];
  }

  // Return only users assigned to this sub-admin
  return users.filter(user =>
    subAdmin.assignedUsers.includes(user.username) && !user.isSubAdmin
  );
}

// module.exports = filterNonSubAdmins;

module.exports = {
  filterNonSubAdmins,
  filterUsersForSubAdmin
};