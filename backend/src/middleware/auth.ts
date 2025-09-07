import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { Environment } from '../config/environment';
import { UserModel } from '../models/users';
import type { AuthTokenPayload, User } from '../types/user';

// Extend Express Request interface to include user
declare global {
  namespace Express {
    interface Request {
      user?: User;
    }
  }
}

// Extract token from Authorization header
const extractTokenFromHeader = (authHeader: string | undefined): string | null => {
  if (!authHeader) {
    return null;
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return null;
  }

  return parts[1];
};

// Verify JWT token and attach user to request
export const authenticateToken = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const token = extractTokenFromHeader(req.headers.authorization);

    if (!token) {
      res.status(401).json({
        error: 'Authentication required',
        message: 'No token provided',
      });
      return;
    }

    // Verify the JWT token
    const decoded = jwt.verify(token, Environment.JWT_SECRET) as AuthTokenPayload;

    // Find the user in database
    const user = await UserModel.findById(decoded.userId).lean();

    if (!user) {
      res.status(401).json({
        error: 'Authentication failed',
        message: 'User not found',
      });
      return;
    }

    // Convert MongoDB document to User type
    const userData: User = {
      _id: user._id.toString(),
      googleId: user.googleId,
      email: user.email,
      name: user.name,
      profilePicture: user.profilePicture,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };

    // Attach user to request object
    req.user = userData;
    next();
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      res.status(401).json({
        error: 'Authentication failed',
        message: 'Invalid token',
      });
      return;
    }

    if (error instanceof jwt.TokenExpiredError) {
      res.status(401).json({
        error: 'Authentication failed',
        message: 'Token expired',
      });
      return;
    }

    console.error('Authentication middleware error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'Authentication check failed',
    });
  }
};

// Optional authentication - doesn't fail if no token provided
export const optionalAuth = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const token = extractTokenFromHeader(req.headers.authorization);

    if (!token) {
      next();
      return;
    }

    // Try to verify token, but don't fail if invalid
    const decoded = jwt.verify(token, Environment.JWT_SECRET) as AuthTokenPayload;
    const user = await UserModel.findById(decoded.userId).lean();

    if (user) {
      const userData: User = {
        _id: user._id.toString(),
        googleId: user.googleId,
        email: user.email,
        name: user.name,
        profilePicture: user.profilePicture,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      };
      req.user = userData;
    }

    next();
  } catch (error) {
    // Silently continue without authentication
    next();
  }
};
