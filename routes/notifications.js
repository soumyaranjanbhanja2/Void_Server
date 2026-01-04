import express from 'express';
import Notification from '../models/Notification.js';
import { requireAuth, requireAdmin } from '../middleware/auth.js';

const router = express.Router();

router.get('/public', async (_, res) => {
  const items = await Notification.find({ active: true }).sort({ createdAt: -1 });
  res.json(items);
});

router.post('/', requireAuth, requireAdmin, async (req, res) => {
  const { title, message, priority } = req.body;
  const item = await Notification.create({ title, message, priority });
  res.status(201).json(item);
});

export default router;