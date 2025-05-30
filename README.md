<p align="center">
<img alt="NPM Version" src="https://img.shields.io/npm/v/%40albirex%2Ffastify-logto">
<img alt="GitHub License" src="https://img.shields.io/github/license/albiper/fastify-logto">
<img alt="GitHub Actions Workflow Status" src="https://img.shields.io/github/actions/workflow/status/albiper/fastify-logto/npm-publish.yml">
<img alt="NPM Downloads" src="https://img.shields.io/npm/dm/%40albirex%2Ffastify-logto">
</p>
<br/>

# Fastify Logto Integration
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
## License
This project is licensed under the MIT License.

## Contributing
Contributions are welcome! Please open an issue or submit a pull request for any enhancements or bug fixes.

For more information and advanced usage, please refer to the official documentation for [Platformatic](https://platformatic.dev/docs/db/plugin) and [LogTo](https://docs.logto.io/introduction).