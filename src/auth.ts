/** @format */

import { betterAuth, BetterAuthOptions, type Auth as BetterAuthType } from 'better-auth';
import { syncFirebaseUser } from './firebase/index.js';
import { createAuthMiddleware } from 'better-auth/api';
import {
	admin,
	bearer,
	customSession,
	deviceAuthorization,
	emailOTP,
	magicLink,
	oAuthProxy,
	oidcProvider,
	organization,
	twoFactor,
	username,
} from 'better-auth/plugins';
import { initializeApp, getApps, cert } from 'firebase-admin/app';
import { EnvironmentUtils } from '@hashibutogarasu/common';
import { passwordPlugin } from './plugins/password/password-plugin.js';
import { oauthApplicationPlugin } from './plugins/oauth/oauth-application-plugin.js';
import { passkeyPlugin } from './plugins/passkey/passkey-plugin.js';
import { openAPIPlugin } from './plugins/openapi/openapi-plugin.js';
import { blueskyPlugin } from './plugins/bluesky/bluesky-plugin.js';
import { databaseSeedingFactory } from './shared/database/database-seeding.service.js';
import { IPasskeyAuth } from './plugins/passkey/passkey.interface.js';
import { IConfigService } from './shared/config/config.service.interface.js';
import { IDataBaseService } from './shared/database/database.service.interface.js';
import { IAuthConfig } from './services/auth/config/auth-config.interface.js';
import { ISocialProviderConfig } from './services/auth/socialProvider/social-provider-config.interface.js';
import { IAuthNotificationService } from './services/auth/notification/auth-notification.service.interface.js';
import { IBetterAuthBootStrapper } from './bootstrap/better-auth-bootstrapper.interface.js';
import { I18nBootStrapper } from './bootstrap/i18n.bootstrapper.js';
import { DatabaseSeedingBootStrapper } from './bootstrap/database-seeding.bootstrapper.js';
import { AuthEnvironment } from './auth-environment.js';
import { AuthBootstrapContext } from './bootstrap/auth-bootstrap.context.js';
import { InitializeEnv } from './bootstrap/initialize-env.js';
import { ValidEnv } from './bootstrap/valid-env.js';
import { InitializeConfig } from './bootstrap/initialize-config.js';
import { InitializeService } from './bootstrap/initialize-service.js';
import { ErrorCodes } from './shared/errors/error.codes.js';
import { IAdminConfig } from './services/auth/admin/admin-config.interface.js';
import { IRateLimitConfig } from './services/auth/rateLimit/rate-limit-config.interface.js';
import { dash } from '@better-auth/infra';
import { createFirebaseCustomToken } from './firebase/index.js';
import { apiKey } from '@better-auth/api-key';

export function createAuth(
	configService: IConfigService,
	dbService: IDataBaseService,
	notificationService: IAuthNotificationService,
	passkeyAuth: IPasskeyAuth,
	authConfig: IAuthConfig,
	socialProviderConfig: ISocialProviderConfig,
	adminConfig: IAdminConfig,
	rateLimitConfig: IRateLimitConfig,
	overrides: Partial<BetterAuthOptions> = {}
): BetterAuthType {
	const env = configService.getAll();
	const authEnv = new AuthEnvironment(env.NODE_ENV);

	const normalizePrivateKey = (value?: string): string | undefined => {
		if (!value) {
			return undefined;
		}
		const trimmed = value.trim();
		const unquoted = trimmed.replace(/^"|"$/g, '').replace(/^'|'$/g, '');
		return unquoted.replace(/\\n/g, '\n').replace(/\r\n?/g, '\n');
	};

	if (env.FIREBASE_PROJECT_ID && !getApps().length) {
		initializeApp({
			credential: cert({
				projectId: env.FIREBASE_PROJECT_ID,
				clientEmail: env.FIREBASE_CLIENT_EMAIL,
				privateKey: normalizePrivateKey(env.FIREBASE_PRIVATE_KEY),
			}),
		});
	}

	const socialProviders = {
		...socialProviderConfig.getBuiltinProviders(),
		...(overrides.socialProviders ?? {}),
	};

	let authInstance: BetterAuthType;

	authInstance = betterAuth({
		baseURL: env.BETTER_AUTH_URL,
		basePath: '/api/auth',
		secret: env.BETTER_AUTH_SECRET,
		appName: 'Karasu Lab',
		trustedOrigins: [
			...authConfig.getTrustedOrigins(),
			...(Array.isArray(overrides.trustedOrigins) ? overrides.trustedOrigins : []),
		],
		advanced: {
			crossSubDomainCookies: authConfig.getCrossSubDomainCookies(),
			trustHost: true,
		},
		trustedProxyHeaders: true,
		ipAddressHeaders: ['cf-connecting-ip', 'x-forwarded-for'],
		cookieCache: {
			enabled: EnvironmentUtils.isProduction(authEnv.environment),
			strategy: 'jwe',
			maxAge: 300,
		},
		logger: {
			level: EnvironmentUtils.isProduction(authEnv.environment) ? 'info' : 'debug',
			disabled: false,
		},
		rateLimit: overrides.rateLimit ?? rateLimitConfig.getConfig(),
		experimental: {
			joins: true,
		},
		emailAndPassword: {
			enabled: true,
			requireEmailVerification: true,
		},
		emailVerification: {
			sendVerificationEmail: async ({ user, url }) => {
				await notificationService.sendVerificationEmail({ user, url });
			},
			sendOnSignUp: true,
			sendOnSignIn: true,
		},
		socialProviders,
		hooks: {
			after: createAuthMiddleware(async (context) => {
				if (context.path === '/oauth2/consent' || context.path === '/sign-out') {
					const expiredDate = new Date(0).toUTCString();
					const oidcCookies = ['oidc_login_prompt', 'oidc_consent_prompt'];
					oidcCookies.forEach((cookieName) => {
						const setCookie = `${cookieName}=; Expires=${expiredDate}; Max-Age=0; Path=/; SameSite=lax`;
						context.setHeader('Set-Cookie', setCookie);
					});
				}
				if (context.path === '/oauth2/token') {
					const returned = context.context.returned as Record<string, unknown> | undefined;
					if (returned && typeof returned.access_token === 'string') {
						if (authInstance) {
							const session = await authInstance.api.getSession({
								headers: context.request.headers,
							});
							if (session) {
								const token = session.session.token;
								const isSecure = context.request.url.startsWith('https');
								const cookieName = isSecure
									? '__Secure-better-auth.session_token'
									: 'better-auth.session_token';
								const setCookie = `${cookieName}=${token}; Path=/; HttpOnly; SameSite=Lax${isSecure ? '; Secure' : ''}`;
								context.setHeader('Set-Cookie', setCookie);
							}
						}
					}
				}
				if (context.context.newSession) {
					const { user } = context.context.newSession;
					context.context.runInBackground(
						syncFirebaseUser({
							id: user.id,
							email: user.email,
							name: user.name,
						})
					);
				}
				await Promise.resolve();
			}),
		},
		user: {
			deleteUser: { enabled: true },
			changeEmail: {
				enabled: true,
				sendChangeEmailConfirmation: async ({ newEmail, url }) => {
					await notificationService.sendChangeEmailVerification({
						newEmail,
						url,
					});
				},
			},
		},
		account: {
			accountLinking: {
				enabled: true,
				allowDifferentEmails: true,
				trustedProviders: Object.keys(socialProviderConfig.getProviders()),
			},
			updateAccountOnSignIn: true,
		},
		session: {},
		database: dbService.getHandler(),
		plugins: [
			blueskyPlugin(),
			oAuthProxy({
				productionURL: env.FRONTEND_ORIGIN,
			}),
			dash(),
			openAPIPlugin(),
			oidcProvider({ loginPage: '/login', consentPage: '/oauth/authorize' }),
			username(),
			passwordPlugin(),
			oauthApplicationPlugin(),
			passkeyPlugin(passkeyAuth),
			twoFactor(),
			organization(),
			admin({
				adminUserIds: adminConfig.getUserIds(),
			}),
			apiKey({ enableSessionForAPIKeys: true }),
			deviceAuthorization(),
			bearer(),
			emailOTP({
				storeOTP: 'hashed',
				sendVerificationOTP: async ({ email, otp, type }) => {
					await notificationService.sendVerificationOTP({ email, otp, type });
				},
				sendVerificationOnSignUp: false,
			}),
			magicLink({
				storeToken: 'hashed',
				sendMagicLink: async ({ email, token }) => {
					await notificationService.sendMagicLink({ email, token });
				},
			}),
			customSession(
				async ({ user, session }) => {
					const firebaseIdToken = await createFirebaseCustomToken(user.id);
					return {
						user,
						session,
						firebaseIdToken,
					};
				},
				{},
				{ shouldMutateListDeviceSessionsEndpoint: true }
			),
			...(overrides.plugins ?? []),
		],
	}) as unknown as BetterAuthType;

	return authInstance;
}

let cachedAuth: BetterAuthType | null = null;

export async function initAuth(): Promise<BetterAuthType> {
	if (cachedAuth) {
		return cachedAuth;
	}

	const context = new AuthBootstrapContext();

	if (context.authEnv && EnvironmentUtils.isTest(context.authEnv.environment)) {
		cachedAuth = context.auth!;
		return cachedAuth;
	}

	const bootstrappers: IBetterAuthBootStrapper[] = [
		new InitializeEnv(context),
		new ValidEnv(context),
		new InitializeConfig(context),
		new InitializeService(context, createAuth),
		new I18nBootStrapper(),
	];

	for (const bootstrapper of bootstrappers) {
		await bootstrapper.bootstrap();
	}

	if (context.authEnv && context.dbService) {
		await new DatabaseSeedingBootStrapper(
			databaseSeedingFactory(context.dbService.prisma)
		).bootstrap();
	}

	if (!context.auth) {
		throw ErrorCodes.SYSTEM.AUTH_INITIALIZATION_FAILED;
	}

	cachedAuth = context.auth;
	return cachedAuth;
}

export const auth: BetterAuthType = await initAuth();
