import { Request, Response, NextFunction } from 'express';
import { Environment } from '../config/environment';

// Error interface
interface AppError extends Error {
  statusCode?: number;
  isOperational?: boolean;
}

// Global error handling middleware
export const errorHandler = (
  error: AppError,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  let statusCode = error.statusCode || 500;
  let message = error.message || 'Internal server error';

  // Log error details
  console.error('Error:', {
    statusCode,
    message,
    stack: error.stack,
    url: req.url,
    method: req.method,
    timestamp: new Date().toISOString(),
  });

  // Handle specific MongoDB errors
  if (error.name === 'ValidationError') {
    statusCode = 400;
    message = 'Validation error';
  } else if (error.name === 'CastError') {
    statusCode = 400;
    message = 'Invalid ID format';
  } else if (error.name === 'MongoServerError' && (error as any).code === 11000) {
    statusCode = 409;
    message = 'Duplicate field value';
  }

  // Response object
  const errorResponse: any = {
    error: 'Request failed',
    message,
  };

  // Include stack trace in development
  if (Environment.NODE_ENV === 'development') {
    errorResponse.stack = error.stack;
    errorResponse.details = {
      name: error.name,
      statusCode,
    };
  }

  res.status(statusCode).json(errorResponse);
};
