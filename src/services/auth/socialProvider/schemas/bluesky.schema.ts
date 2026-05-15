import { z } from 'zod';

export const blueskyProfileSchema = z.object({
  sub: z.string(),
  name: z.string().optional(),
  preferred_username: z.string().optional(),
  picture: z.string().url().optional(),
});

export type BlueskyProfile = z.infer<typeof blueskyProfileSchema>;
