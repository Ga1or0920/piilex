// Service that handles PII - exports functions dealing with personal data

export interface UserData {
  email: string;
  fullName: string;
  phone: string;
  ssn: string;
}

export function getUserEmail(userId: string): string {
  return db.query("SELECT email FROM users WHERE id = $1", [userId]);
}

export function getUserProfile(userId: string): UserData {
  return db.query("SELECT * FROM users WHERE id = $1", [userId]);
}

export const API_SECRET = process.env.API_SECRET;
