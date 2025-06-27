function filterNonSubAdmins(users) {
  return users.filter(user => !user.isSubAdmin);
}


module.exports = filterNonSubAdmins;