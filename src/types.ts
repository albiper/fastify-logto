import type { GetContextParameters, LogtoConfig, SignInOptions } from '@logto/node';

export type LogtoFastifyConfig = LogtoConfig & {
  createAuthRoutes?: boolean;
  authRoutesPrefix?: string;
  signInOptions?: Omit<SignInOptions, 'redirectUri' | 'postRedirectUri'>;
  baseUrl?: string;
  appId: string;
  appSecret: string;
} & GetContextParameters;
