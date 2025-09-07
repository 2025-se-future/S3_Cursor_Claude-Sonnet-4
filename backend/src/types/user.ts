import { z } from 'zod';

// Base user interface
export interface User {
  _id: string;
  googleId: string;
  email: string;
  name: string;
  profilePicture?: string;
  createdAt: Date;
  updatedAt: Date;
}

// User creation input (from Google OAuth)
export interface CreateUserInput {
  googleId: string;
  email: string;
  name: string;
  profilePicture?: string;
}

// Authentication token payload
export interface AuthTokenPayload {
  userId: string;
  email: string;
  iat?: number;
  exp?: number;
}

// Google OAuth token verification
export interface GoogleTokenPayload {
  sub: string; // Google user ID
  email: string;
  name: string;
  picture?: string;
}

// Authentication response
export interface AuthResponse {
  user: User;
  token: string;
}

// Validation schemas
export const GoogleTokenSchema = z.object({
  token: z.string().min(1, 'Google token is required'),
});

export const SignOutSchema = z.object({
  token: z.string().min(1, 'Token is required'),
});

export type GoogleTokenRequest = z.infer<typeof GoogleTokenSchema>;
export type SignOutRequest = z.infer<typeof SignOutSchema>;
