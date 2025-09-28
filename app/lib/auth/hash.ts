// lib/auth/hash.ts
import bcrypt from 'bcrypt';

// Adjust salt rounds as needed (10 is a safe default)
const SALT_ROUNDS = 10;

export async function hashPassword(password: string) {
    return bcrypt.hash(password, SALT_ROUNDS);
}

export async function verifyPassword(password: string, hashedPassword: string) {
    return bcrypt.compare(password, hashedPassword);
}
