import { BetterAuthPlugin } from 'better-auth';
import { openAPI as defaultOpenAPI } from 'better-auth/plugins';
import { AbstractPluginEnvironment } from '../../shared/plugin/abstract-plugin-environment.js';
import { Environment } from '@hashibutogarasu/common';

class ProductionOpenAPIEnvironment extends AbstractPluginEnvironment {
  resolve(): BetterAuthPlugin {
    return defaultOpenAPI();
  }
}

class DevelopmentOpenAPIEnvironment extends AbstractPluginEnvironment {
  resolve(): BetterAuthPlugin {
    return defaultOpenAPI();
  }
}

class TestOpenAPIEnvironment extends AbstractPluginEnvironment {
  resolve(): BetterAuthPlugin {
    return defaultOpenAPI();
  }
}

export const openAPIPlugin = (): BetterAuthPlugin => {
  return AbstractPluginEnvironment.resolve({
    [Environment.PRODUCTION]: ProductionOpenAPIEnvironment,
    [Environment.DEVELOPMENT]: DevelopmentOpenAPIEnvironment,
    [Environment.TEST]: TestOpenAPIEnvironment,
  });
};
