import { describe, it, expect, beforeEach } from 'vitest';
import { API_BASE_KEY, ApiError, getApiBase, setApiBase } from './client';

describe('client', () => {
  beforeEach(() => {
    localStorage.removeItem(API_BASE_KEY);
  });

  it('should have default API base', () => {
    expect(getApiBase()).toBe('/api');
  });

  it('should read API base from localStorage override', () => {
    localStorage.setItem(API_BASE_KEY, '/api-go');
    expect(getApiBase()).toBe('/api-go');
  });

  it('should fall back to default for invalid API base', () => {
    localStorage.setItem(API_BASE_KEY, 'http://example.com');
    expect(getApiBase()).toBe('/api');
  });

  it('should normalize via setApiBase', () => {
    expect(setApiBase('/api-go')).toBe('/api-go');
    expect(getApiBase()).toBe('/api-go');
    expect(setApiBase('invalid')).toBe('/api');
    expect(getApiBase()).toBe('/api');
  });

  it('should create ApiError with status and body', () => {
    const error = new ApiError(404, { message: 'Not found' });
    expect(error.status).toBe(404);
    expect(error.body).toEqual({ message: 'Not found' });
    expect(error.message).toBe('API Error 404');
  });
});
