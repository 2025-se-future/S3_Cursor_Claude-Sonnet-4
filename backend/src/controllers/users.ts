import { Request, Response } from 'express';
import { UserService } from '../services/users';
import { GoogleTokenSchema } from '../types/user';
import type { AuthResponse } from '../types/user';

export class UserController {
  // Sign in with Google
  static async signInWithGoogle(req: Request, res: Response): Promise<void> {
    try {
      // Validate request body
      const validationResult = GoogleTokenSchema.safeParse(req.body);
      if (!validationResult.success) {
        res.status(400).json({
          error: 'Validation failed',
          message: 'Invalid request body',
          details: validationResult.error.errors,
        });
        return;
      }

      const { token } = validationResult.data;

      // Authenticate with Google
      const authResponse: AuthResponse = await UserService.authenticateWithGoogle(token);

      res.status(200).json({
        success: true,
        data: authResponse,
      });
    } catch (error) {
      console.error('Sign in error:', error);

      if (error instanceof Error) {
        if (error.message === 'Invalid Google token') {
          res.status(401).json({
            error: 'Authentication failed',
            message: 'Invalid Google token',
          });
          return;
        }
      }

      res.status(500).json({
        error: 'Internal server error',
        message: 'Sign in failed',
      });
    }
  }

  // Sign out
  static async signOut(req: Request, res: Response): Promise<void> {
    try {
      // User authentication is handled by middleware
      // The token is already validated at this point
      
      const result = await UserService.signOut();

      res.status(200).json({
        success: true,
        data: result,
      });
    } catch (error) {
      console.error('Sign out error:', error);

      res.status(500).json({
        error: 'Internal server error',
        message: 'Sign out failed',
      });
    }
  }

  // Get current user profile
  static async getCurrentUser(req: Request, res: Response): Promise<void> {
    try {
      // User is attached to request by authentication middleware
      const user = req.user;

      if (!user) {
        res.status(401).json({
          error: 'Authentication required',
          message: 'User not found',
        });
        return;
      }

      res.status(200).json({
        success: true,
        data: user,
      });
    } catch (error) {
      console.error('Get current user error:', error);

      res.status(500).json({
        error: 'Internal server error',
        message: 'Failed to get user profile',
      });
    }
  }

  // Get user by ID
  static async getUserById(req: Request, res: Response): Promise<void> {
    try {
      const { userId } = req.params;

      if (!userId) {
        res.status(400).json({
          error: 'Validation failed',
          message: 'User ID is required',
        });
        return;
      }

      const user = await UserService.getUserById(userId);

      if (!user) {
        res.status(404).json({
          error: 'Not found',
          message: 'User not found',
        });
        return;
      }

      res.status(200).json({
        success: true,
        data: user,
      });
    } catch (error) {
      console.error('Get user by ID error:', error);

      res.status(500).json({
        error: 'Internal server error',
        message: 'Failed to get user',
      });
    }
  }
}
