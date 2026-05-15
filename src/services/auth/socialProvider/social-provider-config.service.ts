/* eslint-disable no-empty */
import { IConfigService } from '../../../shared/config/config.service.interface.js';
import {
  ISocialProvider,
  ISocialProviderConfig,
} from './social-provider-config.interface.js';
import {
  OAuthTokenResponse,
  SocialProviderConfig,
  UnifiedProfile,
  oauthTokenResponseSchema,
} from './types/social-provider.js';
import { discordProfileSchema } from './schemas/discord.schema.js';
import { googleProfileSchema } from './schemas/google.schema.js';
import { microsoftProfileSchema } from './schemas/microsoft.schema.js';
import {
  parseEnvelope,
  symmetricDecrypt,
  symmetricEncrypt,
} from 'better-auth/crypto';
import {
  buildSecretConfig,
  createDpopProof,
} from '../../../plugins/bluesky/dpop.js';

/**
 * Abstract base class for social provider
 */
abstract class AbstractSocialProvider implements ISocialProvider {
  abstract readonly id: string;
  abstract readonly name: string;
  abstract readonly isBuiltin: boolean;

  constructor(protected configService: IConfigService) {}

  abstract isEnabled(): boolean;
  abstract getCredentials(): { clientId: string; clientSecret: string } | null;
  getScope?(): string[];
  getAuthorizationQuery?(): Record<string, string>;
  getEndpoints?(): {
    authorizationEndpoint: string;
    tokenEndpoint: string;
    userInfoEndpoint: string;
  };
  abstract getProfile(accessToken: string): Promise<UnifiedProfile | null>;

  async refreshTokens(
    refreshToken: string,
  ): Promise<OAuthTokenResponse | null> {
    const endpoints = this.getEndpoints?.();
    const tokenEndpoint = endpoints?.tokenEndpoint;
    if (!tokenEndpoint) return null;

    const credentials = this.getCredentials();
    if (!credentials) return null;

    const response = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: credentials.clientId,
        client_secret: credentials.clientSecret,
      }),
    });

    if (!response.ok) return null;
    const json = await response.json();
    const data = oauthTokenResponseSchema.parse(json);
    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      expiresIn: data.expires_in,
    };
  }
}

/**
 * Discord OAuth provider
 */
class DiscordProvider extends AbstractSocialProvider {
  readonly id = 'discord';
  readonly name = 'Discord';
  readonly isBuiltin = true;

  isEnabled(): boolean {
    const env = this.configService.getAll();
    return !!(env.DISCORD_CLIENT_ID && env.DISCORD_CLIENT_SECRET);
  }

  getCredentials(): { clientId: string; clientSecret: string } | null {
    if (!this.isEnabled()) return null;

    const env = this.configService.getAll();
    return {
      clientId: env.DISCORD_CLIENT_ID,
      clientSecret: env.DISCORD_CLIENT_SECRET,
    };
  }

  async getProfile(accessToken: string): Promise<UnifiedProfile | null> {
    const response = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!response.ok) return null;
    const json = await response.json();
    const data = discordProfileSchema.parse(json);
    return {
      id: data.id,
      name: data.username,
      email: data.email,
      image: data.avatar
        ? `https://cdn.discordapp.com/avatars/${data.id}/${data.avatar}.png`
        : undefined,
    };
  }

  getEndpoints() {
    return {
      authorizationEndpoint: 'https://discord.com/api/oauth2/authorize',
      tokenEndpoint: 'https://discord.com/api/oauth2/token',
      userInfoEndpoint: 'https://discord.com/api/users/@me',
    };
  }
}

/**
 * Google OAuth provider
 */
class GoogleProvider extends AbstractSocialProvider {
  readonly id = 'google';
  readonly name = 'Google';
  readonly isBuiltin = true;

  isEnabled(): boolean {
    const env = this.configService.getAll();
    return !!(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET);
  }

  getCredentials(): { clientId: string; clientSecret: string } | null {
    if (!this.isEnabled()) return null;

    const env = this.configService.getAll();
    return {
      clientId: env.GOOGLE_CLIENT_ID,
      clientSecret: env.GOOGLE_CLIENT_SECRET,
    };
  }

  getEndpoints() {
    return {
      authorizationEndpoint: 'https://accounts.google.com/o/oauth2/auth',
      tokenEndpoint: 'https://oauth2.googleapis.com/token',
      userInfoEndpoint: 'https://www.googleapis.com/oauth2/v3/userinfo',
    };
  }

  async getProfile(accessToken: string): Promise<UnifiedProfile | null> {
    const response = await fetch(
      'https://www.googleapis.com/oauth2/v3/userinfo',
      {
        headers: { Authorization: `Bearer ${accessToken}` },
      },
    );
    if (!response.ok) return null;
    const json = await response.json();
    const data = googleProfileSchema.parse(json);
    return {
      id: data.sub,
      name: data.name,
      email: data.email,
      image: data.picture,
    };
  }
}

/**
 * Microsoft OAuth provider
 */
class MicrosoftProvider extends AbstractSocialProvider {
  readonly id = 'microsoft';
  readonly name = 'Microsoft';
  readonly isBuiltin = true;

  isEnabled(): boolean {
    const env = this.configService.getAll();
    return !!(env.MICROSOFT_CLIENT_ID && env.MICROSOFT_CLIENT_SECRET);
  }

  getCredentials(): {
    clientId: string;
    clientSecret: string;
    tenantId?: string;
  } | null {
    if (!this.isEnabled()) return null;

    const env = this.configService.getAll();
    return {
      clientId: env.MICROSOFT_CLIENT_ID,
      clientSecret: env.MICROSOFT_CLIENT_SECRET,
      tenantId: env.MICROSOFT_TENANT_ID,
    };
  }

  getScope(): string[] {
    return ['openid', 'profile', 'email', 'offline_access'];
  }

  async getProfile(accessToken: string): Promise<UnifiedProfile | null> {
    const response = await fetch('https://graph.microsoft.com/v1.0/me', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!response.ok) return null;
    const json = await response.json();
    const data = microsoftProfileSchema.parse(json);

    let image: string | undefined;
    try {
      const photoResponse = await fetch(
        'https://graph.microsoft.com/v1.0/me/photo/$value',
        {
          headers: { Authorization: `Bearer ${accessToken}` },
        },
      );
      if (photoResponse.ok) {
        const buffer = await photoResponse.arrayBuffer();
        const contentType =
          photoResponse.headers.get('content-type') || 'image/jpeg';
        const base64 = Buffer.from(buffer).toString('base64');
        image = `data:${contentType};base64,${base64}`;
      }
    } catch {}

    return {
      id: data.id,
      name: data.displayName,
      email: data.mail || data.userPrincipalName,
      image,
    };
  }

  getEndpoints() {
    const credentials = this.getCredentials();
    const tenantId = credentials?.tenantId || 'common';
    return {
      authorizationEndpoint: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize`,
      tokenEndpoint: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
      userInfoEndpoint: 'https://graph.microsoft.com/v1.0/me',
    };
  }
}

/**
 * Bluesky OAuth provider
 */
class BlueskyProvider extends AbstractSocialProvider {
  readonly id = 'bluesky';
  readonly name = 'Bluesky';
  readonly isBuiltin = false;

  isEnabled(): boolean {
    const env = this.configService.getAll();
    return !!env.BETTER_AUTH_URL;
  }

  getCredentials(): { clientId: string; clientSecret: string } | null {
    if (!this.isEnabled()) return null;

    const env = this.configService.getAll();
    return {
      clientId: `${env.BETTER_AUTH_URL}/api/bluesky/oauth/client-metadata.json`,
      clientSecret: '',
    };
  }

  getScope(): string[] {
    return ['atproto', 'transition:generic'];
  }

  getEndpoints(): {
    authorizationEndpoint: string;
    tokenEndpoint: string;
    userInfoEndpoint: string;
  } {
    return {
      authorizationEndpoint: 'https://bsky.social/oauth/authorize',
      tokenEndpoint: 'https://bsky.social/oauth/token',
      userInfoEndpoint: 'https://bsky.social/oauth/userinfo',
    };
  }

  async getProfile(accessToken: string): Promise<UnifiedProfile | null> {
    let did: string | null = null;
    try {
      const parts = accessToken.split('.');
      if (parts.length === 3) {
        const decoded = JSON.parse(
          Buffer.from(parts[1], 'base64url').toString(),
        ) as Record<string, unknown>;
        if (typeof decoded.sub === 'string') did = decoded.sub;
      }
    } catch {
      return null;
    }
    if (!did) return null;

    try {
      const res = await fetch(
        `https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=${encodeURIComponent(did)}`,
      );
      if (!res.ok) return { id: did };
      const profile = (await res.json()) as Record<string, unknown>;
      return {
        id: did,
        name:
          typeof profile.displayName === 'string'
            ? profile.displayName
            : undefined,
        handle: typeof profile.handle === 'string' ? profile.handle : undefined,
        image: typeof profile.avatar === 'string' ? profile.avatar : undefined,
      };
    } catch {
      return { id: did };
    }
  }

  override async refreshTokens(
    refreshToken: string,
  ): Promise<OAuthTokenResponse | null> {
    const secret = this.configService.get('BLUESKY_REFRESH_TOKEN_SECRET');
    const endpoints = this.getEndpoints();
    const credentials = this.getCredentials();
    if (!credentials) return null;

    let plainToken = refreshToken;
    if (secret && parseEnvelope(refreshToken)) {
      try {
        plainToken = await symmetricDecrypt({
          key: buildSecretConfig(secret),
          data: refreshToken,
        });
      } catch {
        return null;
      }
    }

    const doRequest = async (nonce?: string) => {
      const dpopProof = await createDpopProof(
        'POST',
        endpoints.tokenEndpoint,
        nonce,
      );
      const body = new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: plainToken,
        client_id: credentials.clientId,
      });
      const res = await fetch(endpoints.tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          DPoP: dpopProof,
        },
        body,
      });
      const data = (await res.json()) as Record<string, unknown>;
      return { ok: res.ok, data, dpopNonce: res.headers.get('DPoP-Nonce') };
    };

    let result = await doRequest();
    if (
      !result.ok &&
      result.data.error === 'use_dpop_nonce' &&
      result.dpopNonce
    ) {
      result = await doRequest(result.dpopNonce);
    }
    if (!result.ok) return null;

    const newAccessToken =
      typeof result.data.access_token === 'string'
        ? result.data.access_token
        : null;
    if (!newAccessToken) return null;

    let newRefreshToken =
      typeof result.data.refresh_token === 'string'
        ? result.data.refresh_token
        : undefined;
    if (secret && newRefreshToken) {
      newRefreshToken = await symmetricEncrypt({
        key: buildSecretConfig(secret),
        data: newRefreshToken,
      });
    }

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      expiresIn:
        typeof result.data.expires_in === 'number'
          ? result.data.expires_in
          : undefined,
    };
  }
}

/**
 * Social provider configuration service
 * Aggregates all social providers and provides their configurations
 */
export class SocialProviderConfigService implements ISocialProviderConfig {
  private providers: ISocialProvider[];

  constructor(configService: IConfigService) {
    this.providers = [
      new DiscordProvider(configService),
      new GoogleProvider(configService),
      new MicrosoftProvider(configService),
      new BlueskyProvider(configService),
    ];
  }

  getProviders(): Record<string, SocialProviderConfig> {
    const result: Record<string, SocialProviderConfig> = {};

    for (const provider of this.providers) {
      const config = this.getProviderConfig(provider);
      if (config) {
        result[provider.id] = config;
      }
    }

    return result;
  }

  getBuiltinProviders(): Record<string, SocialProviderConfig> {
    const result: Record<string, SocialProviderConfig> = {};

    for (const provider of this.providers) {
      if (provider.isBuiltin) {
        const config = this.getProviderConfig(provider);
        if (config) {
          result[provider.id] = config;
        }
      }
    }

    return result;
  }

  getCustomProviders(): Record<string, SocialProviderConfig> {
    const result: Record<string, SocialProviderConfig> = {};

    for (const provider of this.providers) {
      if (!provider.isBuiltin) {
        const config = this.getProviderConfig(provider);
        if (config) {
          result[provider.id] = config;
        }
      }
    }

    return result;
  }

  private getProviderConfig(
    provider: ISocialProvider,
  ): SocialProviderConfig | null {
    const credentials = provider.getCredentials();
    if (!credentials) return null;

    return {
      id: provider.id,
      name: provider.name,
      ...credentials,
      scope: provider.getScope?.(),
      authorizationQuery: provider.getAuthorizationQuery?.(),
      ...provider.getEndpoints?.(),
    };
  }

  isProviderEnabled(providerId: string): boolean {
    const provider = this.providers.find((p) => p.id === providerId);
    return provider ? provider.isEnabled() : false;
  }

  getProvider(providerId: string): ISocialProvider | undefined {
    return this.providers.find((p) => p.id === providerId);
  }
}

/**
 * Factory function to create social provider config service
 * @param configService Configuration service instance
 * @returns Social provider config service instance
 */
export function socialProviderConfigFactory(
  configService: IConfigService,
): ISocialProviderConfig {
  return new SocialProviderConfigService(configService);
}
