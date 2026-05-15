/* eslint-disable no-empty */
/* eslint-disable @typescript-eslint/only-throw-error */
import type { OAuthProvider } from 'better-auth';
import { BetterAuthPlugin } from 'better-auth';
import { createAuthMiddleware, getOAuthState } from 'better-auth/api';
import { parseEnvelope, symmetricEncrypt } from 'better-auth/crypto';
import {
  createAuthorizationURL,
  authorizationCodeRequest,
  getOAuth2Tokens,
} from '@better-auth/core/oauth2';
import type { OAuth2Tokens } from '@better-auth/core/oauth2';
import { buildSecretConfig, getDpopState, createDpopProof } from './dpop.js';

export type BlueskyOAuthConfig = {
  clientId: string;
  clientSecret?: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  userInfoEndpoint: string;
  scope?: string[];
  authentication?: 'basic' | 'post';
};

type BlueskyPluginOptions = {
  oauth?: BlueskyOAuthConfig | null;
  refreshTokenSecret?: string | null;
};

const buildDefaultOAuthConfig = (): BlueskyOAuthConfig | null => {
  const baseUrl = process.env.BETTER_AUTH_URL;
  if (!baseUrl) return null;

  return {
    clientId: `${baseUrl}/api/bluesky/oauth/client-metadata.json`,
    authorizationEndpoint:
      process.env.BLUESKY_AUTHORIZATION_URL ??
      'https://bsky.social/oauth/authorize',
    tokenEndpoint:
      process.env.BLUESKY_TOKEN_URL ?? 'https://bsky.social/oauth/token',
    userInfoEndpoint:
      process.env.BLUESKY_USERINFO_URL ?? 'https://bsky.social/oauth/userinfo',
    scope: ['atproto', 'transition:generic'],
  };
};

type OAuthTokens = {
  accessToken?: string | null;
};

async function exchangeCodeWithDpop(params: {
  code: string;
  codeVerifier?: string;
  redirectURI: string;
  deviceId?: string;
  tokenEndpoint: string;
  authentication?: 'basic' | 'post';
  clientId: string;
  clientSecret?: string;
}): Promise<OAuth2Tokens> {
  const { body, headers: reqHeaders } = await authorizationCodeRequest({
    code: params.code,
    codeVerifier: params.codeVerifier,
    redirectURI: params.redirectURI,
    deviceId: params.deviceId,
    authentication: params.authentication,
    options: {
      clientId: params.clientId,
      ...(params.clientSecret ? { clientSecret: params.clientSecret } : {}),
    },
  });

  const doRequest = async (nonce?: string) => {
    const dpopProof = await createDpopProof(
      'POST',
      params.tokenEndpoint,
      nonce,
    );
    const res = await fetch(params.tokenEndpoint, {
      method: 'POST',
      body,
      headers: { ...reqHeaders, DPoP: dpopProof },
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

  if (!result.ok) {
    throw result.data;
  }

  return getOAuth2Tokens(result.data);
}

const mapBlueskyUserProfile = (profile: Record<string, unknown>) => {
  const idCandidate =
    profile.sub ?? profile.id ?? profile.did ?? profile.handle;
  const isStringifiableId =
    typeof idCandidate === 'string' ||
    typeof idCandidate === 'number' ||
    typeof idCandidate === 'bigint';

  if (!isStringifiableId) return null;

  const email =
    (typeof profile.email === 'string' ? profile.email : null) ?? null;
  const name =
    (typeof profile.name === 'string' && profile.name) ||
    (typeof profile.display_name === 'string' && profile.display_name) ||
    (typeof profile.handle === 'string' && profile.handle) ||
    undefined;
  const image =
    (typeof profile.picture === 'string' && profile.picture) ||
    (typeof profile.avatar === 'string' && profile.avatar) ||
    undefined;
  const emailVerified = Boolean(
    profile.email_verified ?? profile.emailVerified ?? false,
  );

  return {
    id: String(idCandidate),
    email,
    name,
    image,
    emailVerified,
  };
};

export const blueskyPlugin = (
  options: BlueskyPluginOptions = {},
): BetterAuthPlugin => {
  const oauth = options.oauth ?? buildDefaultOAuthConfig();
  const encryptionKey =
    options.refreshTokenSecret ??
    process.env.BLUESKY_REFRESH_TOKEN_SECRET ??
    null;

  return {
    id: 'bluesky',
    init: (ctx) => {
      if (!oauth) return;

      const provider: OAuthProvider<Record<string, unknown>> = {
        id: 'bluesky',
        name: 'Bluesky',
        async createAuthorizationURL(data): Promise<URL> {
          const { jkt } = await getDpopState();
          const url = new URL(data.redirectURI);
          const dynamicBaseUrl = `${url.protocol}//${url.host}`;
          const oauthOptions = {
            clientId: `${dynamicBaseUrl}/api/bluesky/oauth/client-metadata.json`,
            ...(oauth.clientSecret ? { clientSecret: oauth.clientSecret } : {}),
          };
          const oauthState = await getOAuthState();
          const loginHint =
            typeof oauthState?.loginHint === 'string'
              ? oauthState.loginHint
              : data.loginHint;
          return createAuthorizationURL({
            id: 'bluesky',
            authorizationEndpoint: oauth.authorizationEndpoint,
            redirectURI: data.redirectURI,
            state: data.state,
            codeVerifier: data.codeVerifier,
            scopes: data.scopes ?? oauth.scope,
            loginHint,
            options: {
              ...oauthOptions,
            },
            additionalParams: { dpop_jkt: jkt },
          });
        },
        async validateAuthorizationCode(data) {
          const url = new URL(data.redirectURI);
          const dynamicBaseUrl = `${url.protocol}//${url.host}`;
          return exchangeCodeWithDpop({
            code: data.code,
            codeVerifier: data.codeVerifier,
            redirectURI: data.redirectURI,
            deviceId: data.deviceId,
            tokenEndpoint: oauth.tokenEndpoint,
            authentication: oauth.authentication,
            clientId: `${dynamicBaseUrl}/api/bluesky/oauth/client-metadata.json`,
            clientSecret: oauth.clientSecret,
          });
        },
        async getUserInfo(tokens: OAuthTokens) {
          if (!tokens.accessToken) return null;

          let did: string | null = null;
          try {
            const parts = tokens.accessToken.split('.');
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

          const profile: Record<string, unknown> = { sub: did, did };

          try {
            const profileUrl = `https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=${encodeURIComponent(did)}`;
            const res = await fetch(profileUrl);
            if (res.ok) {
              const bskyProfile = (await res.json()) as Record<string, unknown>;
              if (typeof bskyProfile.handle === 'string')
                profile.handle = bskyProfile.handle;
              if (typeof bskyProfile.displayName === 'string')
                profile.name = bskyProfile.displayName;
              if (typeof bskyProfile.avatar === 'string')
                profile.avatar = bskyProfile.avatar;
            }
          } catch {}

          const user = mapBlueskyUserProfile(profile);
          if (!user) return null;
          return { user, data: profile };
        },
      };

      return {
        context: {
          socialProviders: [provider, ...ctx.socialProviders],
        },
      };
    },
    hooks: {
      after: [
        {
          matcher: (context) => {
            if (!context.path?.includes('/callback')) return false;
            if (context.params?.id !== 'bluesky') return false;
            return true;
          },
          handler: createAuthMiddleware(async (context) => {
            if (!encryptionKey) return;

            const oauthState = await getOAuthState();
            if (!oauthState?.link?.userId) return;

            const accounts =
              await context.context.internalAdapter.findAccountByUserId(
                oauthState.link.userId,
              );
            const blueskyAccount = accounts.find(
              (account) => account.providerId === 'bluesky',
            );

            if (!blueskyAccount?.refreshToken) return;
            if (parseEnvelope(blueskyAccount.refreshToken)) return;

            const encryptedRefreshToken = await symmetricEncrypt({
              key: buildSecretConfig(encryptionKey),
              data: blueskyAccount.refreshToken,
            });

            await context.context.internalAdapter.updateAccount(
              blueskyAccount.id,
              { refreshToken: encryptedRefreshToken },
            );
          }),
        },
      ],
    },
  } satisfies BetterAuthPlugin;
};
