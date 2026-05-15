import { Injectable } from '@nestjs/common';
import { IConfigService } from '../shared/config/config.service.interface.js';
import { getApiConfig } from '../utils/config.util.js';

interface BlueskyClientMetadata {
  client_id: string;
  client_name: string;
  client_uri: string;
  redirect_uris: string[];
  grant_types: string[];
  response_types: string[];
  scope: string;
  token_endpoint_auth_method: string;
  application_type: string;
  dpop_bound_access_tokens: boolean;
}

/** Builds the ATProto OAuth client metadata document for the KarasuLab Android app. */
@Injectable()
export class BlueskyService {
  constructor(private readonly configService: IConfigService) {}

  private normalizeRedirectUri(rawUri: string): string {
    const match = rawUri.match(/^([a-z][a-z0-9+.-]*):\/\/(.*)$/i);
    if (!match) return rawUri;

    const scheme = match[1].toLowerCase();
    if (scheme === 'http' || scheme === 'https') return rawUri;

    return `${scheme}:/${match[2]}`;
  }

  getClientMetadata(providedBaseUrl?: string): BlueskyClientMetadata {
    const baseUrl =
      providedBaseUrl ?? this.configService.get('BETTER_AUTH_URL');
    const clientId = `${baseUrl}/api/bluesky/oauth/client-metadata.json`;
    const baseRedirectUris = getApiConfig().bluesky.redirectUris.map((uri) =>
      this.normalizeRedirectUri(uri),
    );
    const dynamicRedirectUri = `${baseUrl}/api/auth/callback/bluesky`;
    const redirectUris = Array.from(
      new Set([...baseRedirectUris, dynamicRedirectUri]),
    );

    return {
      client_id: clientId,
      client_name: 'KarasuLab',
      client_uri: baseUrl,
      redirect_uris: redirectUris,
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      scope: 'atproto transition:generic',
      token_endpoint_auth_method: 'none',
      application_type: 'native',
      dpop_bound_access_tokens: true,
    };
  }
}
