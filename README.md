# fastify-logto

[![npm version](https://img.shields.io/npm/v/fastify-logto.svg)](https://www.npmjs.com/package/@albirex/fastify-logto)
<!-- [![CI](https://github.com/albiper/fastify-logto/actions/workflows/ci.yml/badge.svg)](https://github.com/albiper/fastify-logto/actions/workflows/ci.yml) -->
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

> 🔐 [Fastify](https://fastify.dev/) plugin for integrating with [Logto](https://logto.io), a modern open-source identity platform.

## Features

- Plug-and-play authentication and session management with Logto.
- Secure route protection using Fastify decorators.
- Works seamlessly with Fastify 4+ and TypeScript.

## Installation
To install the package, use your preferred package manager:

```bash
npm install @albirex/fastify-logto
# or
yarn add @albirex/fastify-logto
# or
pnpm add @albirex/fastify-logto
```

## Usage
### Basic setup
```javascript
import Fastify from 'fastify';
import fastifyLogto from 'fastify-logto';

const app = Fastify();

app.register(fastifyLogto, {
  appId: 'your-logto-app-id',
  appSecret: 'your-logto-app-secret',
  endpoint: 'https://your-logto-endpoint.com',
  baseUrl: 'http://localhost:3000',
  cookieSecret: 'your-cookie-secret', // use a strong secret in production
});

```

### Protecting routes
```javascript
app.get('/profile', {
  preHandler: app.verifyLogto,
  handler: async (request, reply) => {
    const userInfo = await request.getLogtoUser();
    return { user: userInfo };
  }
});
```

## Configuration options
| Property     | Type               | Description                                      |
| ------------ | ------------------ | ------------------------------------------------ |
| appId        | string             | Your Logto application's ID.                     |
| appSecret    | string             | Your Logto application's secret.                 |
| endpoint     | string             | Your Logto server endpoint.                      |
| cookieSecret | string             | Secret used for signing cookies (sessions).      |
| baseUrl      | string, optional   | Your app's base URL (for callback routing).      |
| scopes       | string[], optional | Define the scopes required for your application. |

## API
### Decorators
- request.getLogtoUser(): Retrieves the authenticated user's information.
- app.verifyLogto: PreHandler function to enforce authentication.

## Development
```bash
pnpm install
pnpm build
pnpm test
```
### Local linking
```bash
pnpm link --global
cd ../your-app
pnpm link --global fastify-logto
```