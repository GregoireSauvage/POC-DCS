import { describe, it, expect } from 'vitest';
import { API_BASE, ApiError } from './client';

describe('client', () => {
  it('should have default API_BASE', () => {
    expect(API_BASE).toBe('/api');
  });

  it('should create ApiError with status and body', () => {
    const error = new ApiError(404, { message: 'Not found' });
    expect(error.status).toBe(404);
    expect(error.body).toEqual({ message: 'Not found' });
    expect(error.message).toBe('API Error 404');
  });
});
