import { z } from 'zod';

export const googleProfileSchema = z.object({
  sub: z.string(),
  name: z.string(),
  email: z.string().email(),
  picture: z.string().url(),
});

export type GoogleProfile = z.infer<typeof googleProfileSchema>;
