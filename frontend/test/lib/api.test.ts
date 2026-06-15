import { describe, it, expect } from 'vitest';
import { ApiError } from '../../src/lib/api';

describe('ApiError', () => {
    it('should correctly initialize with a code and message', () => {
        const error = new ApiError('invalid_credentials', 'Invalid username or password');

        expect(error.code).toBe('invalid_credentials');
        expect(error.message).toBe('Invalid username or password');
        expect(error.name).toBe('ApiError');
        expect(error instanceof Error).toBe(true);
    });
});
