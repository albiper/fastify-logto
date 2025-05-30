import { test } from 'tap';
import { equal, deepEqual } from 'node:assert'
import { adminSecret, getServer } from './helper.js'

test('admin access', async (t) => {
    const app = await getServer(t);
    t.after(() => {
        app.close()
    })

    await app.ready();

    const res = await app.logto.callAPI('/api/my-account', 'GET');

    equal(res.status, 200, 'get my account status code');

    // {
    //     const res = await app.inject({
    //         method: 'GET',
    //         url: '/pages',
    //         headers: {
    //             'x-platformatic-admin-secret': adminSecret,
    //         },
    //     })
    //     if (res.statusCode != 200) {
    //         throw res.body;
    //     }

    //     equal(res.statusCode, 200, 'get pages status code')
    //     deepEqual(res.json(), [], 'get pages response')
    // }
});