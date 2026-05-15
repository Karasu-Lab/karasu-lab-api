import { z } from 'zod';

export const microsoftProfileSchema = z.object({
  id: z.string(),
  displayName: z.string(),
  mail: z.string().nullable().optional(),
  userPrincipalName: z.string(),
});

export type MicrosoftProfile = z.infer<typeof microsoftProfileSchema>;
