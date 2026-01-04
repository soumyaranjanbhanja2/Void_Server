const mongoose = require('mongoose');
const NoteSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  content: String
});
module.exports = mongoose.model('Note', NoteSchema);