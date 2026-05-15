import { z } from 'zod';

export const discordProfileSchema = z.object({
  id: z.string(),
  username: z.string(),
  email: z.string().optional(),
  avatar: z.string().nullable(),
});

export type DiscordProfile = z.infer<typeof discordProfileSchema>;
