import app from '../hono/hono';
import result from "../model/result";
import oauthService from "../service/oauth-service";

app.post('/oauth/nodeloc/login', async (c) => {
	const loginInfo = await oauthService.NodeLocLogin(c, await c.req.json());
	return c.json(result.ok(loginInfo))
});

app.post('/oauth/github/login', async (c) => {
	const loginInfo = await oauthService.githubLogin(c, await c.req.json());
	return c.json(result.ok(loginInfo))
});

app.post('/oauth/google/login', async (c) => {
	const loginInfo = await oauthService.googleLogin(c, await c.req.json());
	return c.json(result.ok(loginInfo))
});

app.put('/oauth/bindUser', async (c) => {
	const loginInfo = await oauthService.bindUser(c, await c.req.json());
	return c.json(result.ok(loginInfo))
})
