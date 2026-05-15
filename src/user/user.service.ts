import { Injectable } from '@nestjs/common';
import { AuthService } from '@thallesp/nestjs-better-auth';
import { Auth as BetterAuthType } from 'better-auth';
import { fromNodeHeaders } from 'better-auth/node';
import type { Request } from 'express';

import { SessionService } from '../shared/auth/session.service.js';
import { DeletableDiscoveryService } from '../shared/deletable/deletable-discovery.service.js';
import type { UpdateUserProfileDto } from './dto/update-user-profile.dto.js';
import { ISocialProviderConfig } from '../services/auth/socialProvider/social-provider-config.interface.js';
import { socialProviderConfigFactory } from '../services/auth/socialProvider/social-provider-config.service.js';
import { IConfigService } from '../shared/config/config.service.interface.js';
import { getPrisma } from '../prisma.js';

@Injectable()
export class UserService {
  private readonly socialProviderConfig: ISocialProviderConfig;

  constructor(
    private readonly authService: AuthService<BetterAuthType>,
    private readonly sessionService: SessionService,
    private readonly deletableDiscovery: DeletableDiscoveryService,
    private readonly configService: IConfigService,
  ) {
    this.socialProviderConfig = socialProviderConfigFactory(configService);
  }

  async getProfile(req: Request) {
    const { user } = await this.sessionService.requireSession(req);
    return user;
  }

  async updateProfile(req: Request, dto: UpdateUserProfileDto) {
    const result = await this.authService.instance.api.updateUser({
      body: dto,
      headers: fromNodeHeaders(req.headers),
    });
    return result;
  }

  async deleteUserData(userId: string): Promise<void> {
    const services = this.deletableDiscovery.getDeletableServices();
    for (const service of services) {
      await service.deleteData(userId);
    }
  }

  async getSocialProfile(req: Request, providerId: string) {
    const { user } = await this.sessionService.requireSession(req);
    const prisma = getPrisma();

    const account = await prisma.account.findFirst({
      where: {
        userId: user.id,
        providerId: providerId,
      },
    });

    if (!account?.accessToken) return null;

    const provider = this.socialProviderConfig.getProvider(providerId);
    if (!provider) return null;

    const isExpired =
      account.accessTokenExpiresAt &&
      new Date(account.accessTokenExpiresAt).getTime() < Date.now() + 30000;

    let accessToken = account.accessToken;

    if (isExpired && account.refreshToken) {
      const tokens = await provider.refreshTokens(account.refreshToken);
      if (tokens) {
        accessToken = tokens.accessToken;
        await prisma.account.update({
          where: { id: account.id },
          data: {
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken ?? undefined,
            accessTokenExpiresAt: tokens.expiresIn
              ? new Date(Date.now() + tokens.expiresIn * 1000)
              : undefined,
          },
        });
      }
    }

    let profile = await provider.getProfile(accessToken);

    if (!profile && !isExpired && account.refreshToken) {
      const tokens = await provider.refreshTokens(account.refreshToken);
      if (tokens) {
        await prisma.account.update({
          where: { id: account.id },
          data: {
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken ?? undefined,
            accessTokenExpiresAt: tokens.expiresIn
              ? new Date(Date.now() + tokens.expiresIn * 1000)
              : undefined,
          },
        });
        profile = await provider.getProfile(tokens.accessToken);
      }
    }

    return profile;
  }
}
