import { z } from 'zod';

/**
 * Configuration for a social provider
 */
export type SocialProviderConfig = {
  /**
   * Provider identifier
   */
  id: string;
  /**
   * Provider display name
   */
  name: string;
  /**
   * OAuth client ID
   */
  clientId: string;
  /**
   * OAuth client secret
   */
  clientSecret: string;
  /**
   * Tenant ID (for Microsoft provider)
   */
  tenantId?: string;
  /**
   * OAuth scopes
   */
  scope?: string[];
  /**
   * Additional authorization query parameters
   */
  authorizationQuery?: Record<string, string>;
  /**
   * OAuth authorization endpoint (for custom providers)
   */
  authorizationEndpoint?: string;
  /**
   * OAuth token endpoint (for custom providers)
   */
  tokenEndpoint?: string;
  /**
   * OAuth user info endpoint (for custom providers)
   */
  userInfoEndpoint?: string;
};

export const unifiedProfileSchema = z.object({
  id: z.string(),
  name: z.string().optional(),
  email: z.string().email().optional(),
  image: z.string().url().optional(),
  handle: z.string().optional(),
  url: z.string().url().optional(),
});

export type UnifiedProfile = z.infer<typeof unifiedProfileSchema>;

export const oauthTokenResponseSchema = z.object({
  access_token: z.string(),
  refresh_token: z.string().optional(),
  expires_in: z.number().optional(),
});

export type OAuthTokenResponse = {
  accessToken: string;
  refreshToken?: string;
  expiresIn?: number;
};
