// Logger module that imports PII and leaks it to logs

import { getUserEmail, getUserProfile } from './userService';

export function logUserActivity(userId: string) {
  const email = getUserEmail(userId);
  console.log(`User activity: ${email}`);

  const profile = getUserProfile(userId);
  logger.info(`Profile loaded: ${profile.fullName}`);
}
