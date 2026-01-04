const mongoose = require('mongoose');
const NotificationSchema = new mongoose.Schema({
  message: String,
  imageUrl: String,
  createdAt: { type: Date, default: Date.now }
});
module.exports = mongoose.model('Notification', NotificationSchema);