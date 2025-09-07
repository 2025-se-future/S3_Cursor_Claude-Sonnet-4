import jwt from 'jsonwebtoken';
import { OAuth2Client } from 'google-auth-library';
import { UserModel } from '../models/users';
import { Environment } from '../config/environment';
import type {
  User,
  CreateUserInput,
  AuthTokenPayload,
  GoogleTokenPayload,
  AuthResponse,
} from '../types/user';

// Initialize Google OAuth client
const googleClient = new OAuth2Client(Environment.GOOGLE_CLIENT_ID);

export class UserService {
  // Verify Google token and extract user info
  static async verifyGoogleToken(token: string): Promise<GoogleTokenPayload> {
    try {
      const ticket = await googleClient.verifyIdToken({
        idToken: token,
        audience: Environment.GOOGLE_CLIENT_ID,
      });

      const payload = ticket.getPayload();
      if (!payload) {
        throw new Error('Invalid Google token payload');
      }

      return {
        sub: payload.sub,
        email: payload.email || '',
        name: payload.name || '',
        picture: payload.picture,
      };
    } catch (error) {
      console.error('Google token verification error:', error);
      throw new Error('Invalid Google token');
    }
  }

  // Generate JWT token for user
  static generateAuthToken(userId: string, email: string): string {
    const payload: AuthTokenPayload = {
      userId,
      email,
    };

    return jwt.sign(payload, Environment.JWT_SECRET, {
      expiresIn: Environment.JWT_EXPIRES_IN,
    });
  }

  // Find user by Google ID
  static async findUserByGoogleId(googleId: string): Promise<User | null> {
    const user = await UserModel.findOne({ googleId }).lean();
    if (!user) {
      return null;
    }

    return {
      _id: user._id.toString(),
      googleId: user.googleId,
      email: user.email,
      name: user.name,
      profilePicture: user.profilePicture,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }

  // Find user by email
  static async findUserByEmail(email: string): Promise<User | null> {
    const user = await UserModel.findOne({ email }).lean();
    if (!user) {
      return null;
    }

    return {
      _id: user._id.toString(),
      googleId: user.googleId,
      email: user.email,
      name: user.name,
      profilePicture: user.profilePicture,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }

  // Create new user
  static async createUser(userData: CreateUserInput): Promise<User> {
    const newUser = new UserModel(userData);
    const savedUser = await newUser.save();

    return {
      _id: savedUser._id.toString(),
      googleId: savedUser.googleId,
      email: savedUser.email,
      name: savedUser.name,
      profilePicture: savedUser.profilePicture,
      createdAt: savedUser.createdAt,
      updatedAt: savedUser.updatedAt,
    };
  }

  // Authenticate user with Google token
  static async authenticateWithGoogle(googleToken: string): Promise<AuthResponse> {
    // Verify Google token
    const googlePayload = await this.verifyGoogleToken(googleToken);

    // Check if user exists by Google ID
    let user = await this.findUserByGoogleId(googlePayload.sub);

    if (!user) {
      // Check if user exists by email (in case they previously signed up differently)
      const existingUser = await this.findUserByEmail(googlePayload.email);
      
      if (existingUser) {
        // Update existing user with Google ID
        await UserModel.findByIdAndUpdate(
          existingUser._id,
          { googleId: googlePayload.sub },
          { new: true }
        );
        user = { ...existingUser, googleId: googlePayload.sub };
      } else {
        // Create new user
        const newUserData: CreateUserInput = {
          googleId: googlePayload.sub,
          email: googlePayload.email,
          name: googlePayload.name,
          profilePicture: googlePayload.picture,
        };
        user = await this.createUser(newUserData);
      }
    }

    // Generate JWT token
    const token = this.generateAuthToken(user._id, user.email);

    return {
      user,
      token,
    };
  }

  // Get user by ID
  static async getUserById(userId: string): Promise<User | null> {
    const user = await UserModel.findById(userId).lean();
    if (!user) {
      return null;
    }

    return {
      _id: user._id.toString(),
      googleId: user.googleId,
      email: user.email,
      name: user.name,
      profilePicture: user.profilePicture,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }

  // Sign out user (token validation is handled by middleware)
  static async signOut(): Promise<{ message: string }> {
    // In a more sophisticated implementation, you might want to:
    // 1. Blacklist the token
    // 2. Clear any server-side sessions
    // 3. Log the sign-out event
    
    return {
      message: 'Successfully signed out',
    };
  }
}
