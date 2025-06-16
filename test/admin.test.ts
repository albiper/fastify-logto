import { test } from 'tap';
import { equal, deepEqual } from 'node:assert'
import { adminSecret, getServer } from './helper.js'

test('admin access', async (t) => {
    const app = await getServer(t);
    t.after(() => {
        app.close()
    })

    const scopes: {
        id?: string;
        name: string;
    }[] = [
            {
                name: 'god_powers'
            },
            {
                name: 'find:places'
            }
        ]

    await app.ready();
    {
        const res = await app.logto.callAPI('/api/resources', 'POST', JSON.stringify({
            "name": "test-fastify-logto",
            "indicator": "http://test.fastify-logto.albiper",
            "accessTokenTtl": 3600
        }));

        equal(res.status, 201, 'LogTo resource created');

        const createResource = await res.json();

        for (const [index, scope] of scopes.entries()) {
            const resScope = await app.logto.callAPI(`/api/resources/${createResource.id}/scopes`, 'POST', JSON.stringify({
                "name": scope.name,
            }));

            const json = await resScope.json();
            scopes[index].id = json.id;
            equal(resScope.status, 201, 'LogTo scope created');
        }
    }

    {
        const res = await app.logto.callAPI('/api/roles', 'POST', JSON.stringify({
            "name": "supercow",
            "description": "supercow",
            "type": "User",
            "isDefault": false,
            "scopeIds": scopes.map(scope => scope.id)
        }));
        equal(res.status, 200, 'LogTo supercow role created');

        const resuser = await app.logto.callAPI('/api/roles', 'POST', JSON.stringify({
            "name": "user",
            "description": "user",
            "type": "User",
            "isDefault": true,
            "scopeIds": scopes.filter(scope => scope.name === 'find:places')?.map(scope => scope.id)
        }));
        equal(resuser.status, 200, 'LogTo supercow role created');
    }
});