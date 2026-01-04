import express from 'express';
import Note from '../models/Note.js';
import { requireAuth } from '../middleware/auth.js';

const router = express.Router();

router.get('/', requireAuth, async (req, res) => {
  const notes = await Note.find({ userId: req.user._id }).sort({ updatedAt: -1 });
  res.json(notes);
});

router.post('/', requireAuth, async (req, res) => {
  const { title, content } = req.body;
  const note = await Note.create({ userId: req.user._id, title, content });
  res.status(201).json(note);
});

export default router;