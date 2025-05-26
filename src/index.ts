import NodeClient, { type LogtoContext } from '@logto/node';
import type { FastifyInstance, FastifyPluginAsync, FastifyReply, FastifyRequest, RouteOptions } from 'fastify';
import fp from 'fastify-plugin';
import fastifyCookie from '@fastify/cookie';
import fastifySession from '@fastify/session';

import { LogtoFastifyError } from './errors.js';
import FastifyStorage from './storage.js';
import type { LogtoFastifyConfig } from './types.js';

export type { LogtoFastifyConfig } from './types.js';

export type FastifyLogtoContext = LogtoContext & {
  accessTokenClaims?: string[];
};

const createNodeClient = (
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  request: FastifyRequest & { session?: any },
  reply: FastifyReply,
  config: LogtoFastifyConfig
) => {
  if (!request.session) {
    throw new LogtoFastifyError('session_not_configured');
  }
  const storage = new FastifyStorage(request);

  return new NodeClient(config, {
    storage,
    navigate: async (url) => {
      await reply.redirect(url);
    },
  });
};

const fastifyLogto: FastifyPluginAsync<LogtoFastifyConfig> = async (fastify, config) => {
  let token: string | undefined;
  const prefix = config.authRoutesPrefix ?? 'logto';

  fastify.register(fastifyCookie);
  fastify.register(fastifySession, {
    secret: 'lQutJT2nj63kjq5ThEl7bv5mPIvWqQ0P'
  });

  fastify.decorate('logto', {
    getToken: async () => {
      const res = await fetch(`${config.endpoint}/oidc/token`, {
        method: 'POST',
        headers: {
          Authorization: `Basic ${Buffer.from(`${config.appId}:${config.appSecret}`).toString(
            'base64'
          )}`,
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          scope: 'all',
          resource: 'https://default.logto.app/api',
        }),
      });

      if (!res.ok) {
        throw res;
      }

      token = ((await res.json()) as { access_token: string }).access_token;
      return token;
    },
    callAPI: async (
      url: string,
      method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE',
      body?: BodyInit | undefined | null
    ) => {
      if (!token) {
        await fastify.logto.getToken();
      }

      fastify.log.debug(`Fetching LogTo at URL ${config.endpoint}`);
      const res = await fetch(`${config.endpoint}${url}`, {
        method,
        headers: {
          Authorization: `Bearer ${token}`,
          'content-type': 'application/json',
        },
        body,
      });

      if (!res.ok) {
        if (res.status === 401) {
          const errorBody = await res.json();

          if (errorBody.data.code === 'ERR_JWT_EXPIRED') {
            await fastify.logto.getToken();
            return fastify.logto.callAPI(url, method, body);
          }
        }

        throw res;
      }

      return res;
    },
  });

  fastify.decorate('protectedRoute', (options: RouteOptions) => {
    return fastify.route({
      ...options,
      preHandler: (request: FastifyRequest, response: FastifyReply) => {
        if (!request.logToUser?.isAuthenticated) {
          return response.redirect(`${prefix}/sign-in`);
        }
      },
    });
  });

  // Register Logto auth routes
  if (config.createAuthRoutes) {
    fastify.get(
      `/${prefix}/:action`,
      async (request: FastifyRequest<{ Params: { action: string } }>, reply: FastifyReply) => {
        const { action } = request.params;
        const nodeClient = createNodeClient(request, reply, config);
        switch (action) {
          case 'sign-in': {
            await nodeClient.signIn({
              ...config.signInOptions,
              redirectUri: `${config.baseUrl}/${prefix}/sign-in-callback`,
            });
            break;
          }

          case 'sign-up': {
            await nodeClient.signIn({
              ...config.signInOptions,
              redirectUri: `${config.baseUrl}/${prefix}/sign-in-callback`,
              firstScreen: 'register',
            });
            break;
          }

          case 'sign-in-callback': {
            if (request.raw.url) {
              await nodeClient.handleSignInCallback(`${config.baseUrl}${request.raw.url}`);
              return reply.redirect(config.baseUrl ?? '');
            }
            break;
          }

          case 'sign-out': {
            await nodeClient.signOut(config.baseUrl);
            break;
          }

          default: {
            return reply.status(404).send();
          }
        }
      }
    );
  }

  fastify.decorateRequest('logToUser');

  // Add user context hook
  fastify.addHook('preHandler', async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const client = createNodeClient(request, reply, config);
      const user = await client.getContext({
        getAccessToken: config.getAccessToken,
        resource: config.resource,
        fetchUserInfo: config.fetchUserInfo,
        getOrganizationToken: config.getOrganizationToken,
      });

      if (await client.isAuthenticated()) {
        const at = await client.getAccessTokenClaims('http://test.test');
        // eslint-disable-next-line @silverhand/fp/no-mutation
        request.logToUser = { ...user, accessTokenClaims: at.scope?.split(' ') };
      } else {
        // eslint-disable-next-line @silverhand/fp/no-mutation
        request.logToUser = { ...user };
      }
    } catch {
      // If auth fails or is missing, we skip attaching user
      // Log or handle as needed
    }
  });
};

export const plugin = (fastify: FastifyInstance) => {
  fastify.log.info('test');
};

export default fp(fastifyLogto, {
  name: 'fastify-logto',
});

export type LogToFastifyInstance = {
  getToken: () => Promise<string>;
  callAPI: (url: string, method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE', body?: BodyInit | null) => Promise<Response>;
};

declare module 'fastify' {
  interface FastifyInstance {
    logto: LogToFastifyInstance,
    protectedRoute: (options: RouteOptions) => FastifyInstance;
  }
  interface FastifyRequest {
    logToUser?: FastifyLogtoContext;
  }
}
