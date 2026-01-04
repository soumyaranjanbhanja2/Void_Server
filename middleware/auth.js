import jwt from 'jsonwebtoken';

export const protect = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(auth.split(' ')[1], process.env.JWT_SECRET);
    req.user = decoded; // { id, role }
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  // If header is missing, return 401 (Unauthorized) or 403 (Forbidden)
  const token = authHeader && authHeader.split(' ')[1]; // Get token part after "Bearer"

  if (!token) return res.status(403).send("A token is required for authentication");

  try {
    // Verify token logic here...
    next();
  } catch (err) {
    return res.status(403).send("Invalid Token");
  }
};

export const adminOnly = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};