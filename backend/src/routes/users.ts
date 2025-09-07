import { Router } from 'express';
import { UserController } from '../controllers/users';
import { authenticateToken } from '../middleware/auth';
import rateLimit from 'express-rate-limit';

const router = Router();

// Rate limiting for authentication endpoints
const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 requests per windowMs for auth endpoints
  message: {
    error: 'Too many authentication attempts',
    message: 'Too many requests from this IP, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Public routes (no authentication required)
router.post('/auth/signin', authRateLimit, UserController.signInWithGoogle);

// Protected routes (authentication required)
router.post('/auth/signout', authenticateToken, UserController.signOut);
router.get('/me', authenticateToken, UserController.getCurrentUser);
router.get('/:userId', authenticateToken, UserController.getUserById);

export default router;
