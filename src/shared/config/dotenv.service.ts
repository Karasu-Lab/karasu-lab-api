import dotenv from 'dotenv';
import { IDotEnvService } from './dotenv.service.interface.js';
import { AbstractPluginEnvironment } from '../plugin/abstract-plugin-environment.js';
import { Environment } from '@hashibutogarasu/common';

/**
 * Simple DotEnv service
 */
class DotEnvService
  extends AbstractPluginEnvironment<IDotEnvService>
  implements IDotEnvService
{
  init(): void {
    dotenv.config();
  }

  resolve(): IDotEnvService {
    return this;
  }
}

/**
 * Factory function to create DotEnv service based on environment
 * @returns DotEnv service instance for current environment
 */
export function dotEnvServiceFactory(): IDotEnvService {
  return AbstractPluginEnvironment.resolve<IDotEnvService, DotEnvService, []>({
    [Environment.PRODUCTION]: DotEnvService as new () => DotEnvService,
    [Environment.DEVELOPMENT]: DotEnvService as new () => DotEnvService,
    [Environment.TEST]: DotEnvService as new () => DotEnvService,
  });
}

/**
 * Singleton instance for early initialization in main.ts and tests
 */
export const dotEnvService = dotEnvServiceFactory();

/**
 * NestJS Provider for IDotEnvService
 */
export const DotEnvServiceProvider = {
  provide: IDotEnvService,
  useFactory: dotEnvServiceFactory,
};
