import mongoose, { Schema, Document } from 'mongoose';
import type { User as UserType } from '../types/user';

// User document interface for MongoDB
export interface UserDocument extends Omit<UserType, '_id'>, Document {
  _id: mongoose.Types.ObjectId;
}

// User schema
const userSchema = new Schema<UserDocument>({
  googleId: {
    type: String,
    required: true,
    unique: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  },
  name: {
    type: String,
    required: true,
    trim: true,
  },
  profilePicture: {
    type: String,
    default: undefined,
  },
}, {
  timestamps: true, // Automatically adds createdAt and updatedAt
  versionKey: false, // Disable __v field
});

// Additional indexes for performance
userSchema.index({ createdAt: -1 });

// Transform function to convert MongoDB document to clean JSON
userSchema.set('toJSON', {
  transform: (doc, ret) => {
    ret._id = ret._id.toString();
    return ret;
  },
});

// Create and export the model
export const UserModel = mongoose.model<UserDocument>('User', userSchema);
