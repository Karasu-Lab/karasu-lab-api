import { BetterAuthPlugin } from 'better-auth';
import { openAPI } from 'better-auth/plugins';

export const openAPIPlugin = (): BetterAuthPlugin => {
  return openAPI();
};
