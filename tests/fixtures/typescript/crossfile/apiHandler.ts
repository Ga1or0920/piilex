// API handler that imports PII and sends it to external services

import { getUserProfile, API_SECRET } from './userService';

export async function handleUserExport(req: Request, res: Response) {
  const profile = getUserProfile(req.params.id);

  // PII sent to third-party analytics
  await fetch("https://analytics.example.com/track", {
    method: "POST",
    body: JSON.stringify({ email: profile.email, name: profile.fullName }),
  });

  // PII returned in API response
  res.json({
    user: profile,
    email: profile.email,
  });
}
