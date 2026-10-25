import BizError from "../error/biz-error";
import orm from "../entity/orm";
import {oauth} from "../entity/oauth";
import { eq, inArray } from 'drizzle-orm';
import userService from "./user-service";
import loginService from "./login-service";
import cryptoUtils from "../utils/crypto-utils";
import settingService from "./setting-service";
import {t} from '../i18n/i18n';

const oauthService = {

	async bindUser(c, params) {

		const { email, oauthUserId, code, password } = params;

		const oauthRow = await this.getById(c, oauthUserId);

		let userRow = await userService.selectByIdIncludeDel(c, oauthRow.userId);

		if (userRow) {
			throw new BizError('用户已绑定有邮箱')
		}

		const setting = await settingService.query(c);
		const isNodeLoc = oauthRow.platform === 'nodeloc';
		const trustLevel = Number(oauthRow.trustLevel ?? -1);
		const trustEnough = !isNodeLoc || trustLevel >= Number(setting.nodelocMinTrustLevel || 0);
		if (isNodeLoc && setting.nodelocRegisterSwitch !== 0) {
			throw new BizError('NodeLoc 新用户注册已关闭');
		}
		if (isNodeLoc && !trustEnough && setting.regKey === 0 && !code) {
			throw new BizError('信任等级不足，请输入邀请码');
		}
		const effectivePassword = password || cryptoUtils.genRandomPwd();
		await loginService.register(c, { email, password: effectivePassword, code: isNodeLoc && trustEnough ? '' : code }, true, { skipRegKey: isNodeLoc && trustEnough });

		userRow = await userService.selectByEmail(c, email);

		orm(c).update(oauth).set({ userId: userRow.userId }).where(eq(oauth.oauthUserId, oauthUserId)).run();
		const jwtToken = await loginService.login(c, { email, password: null }, true);

		return { userInfo: oauthRow, token: jwtToken}
	},

	async nodeLocLogin(c, params) {

		const { code, redirectUri } = params;

		const setting = await settingService.query(c);
		this.assertEnabled(setting, 'nodelocSwitch');

		const reqParams = new URLSearchParams()
		reqParams.append('client_id', setting.nodelocClientId)
		reqParams.append('client_secret', setting.nodelocClientSecret)
		reqParams.append('code', code)
		reqParams.append('redirect_uri', redirectUri)
		reqParams.append('grant_type', 'authorization_code')

		const tokenRes = await fetch("https://www.nodeloc.com/oauth-provider/token", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: reqParams.toString()
		})

		if (!tokenRes.ok) {
			throw new BizError(tokenRes.statusText)
		}

		const token = await tokenRes.json()

		const userRes = await fetch('https://www.nodeloc.com/oauth-provider/userinfo', {
			headers: {
				Authorization: 'Bearer ' + token.access_token
			}
		});

		if (!userRes.ok) {
			throw new BizError(userRes.statusText)
		}

		const userInfo = await userRes.json();

		userInfo.oauthUserId = String(userInfo.sub ?? userInfo.id ?? '');
		if (!userInfo.oauthUserId) throw new BizError('NodeLoc 未返回用户唯一标识');
		userInfo.username = userInfo.preferred_username ?? userInfo.username ?? userInfo.email ?? '';
		userInfo.name = userInfo.name ?? userInfo.username;
		userInfo.trustLevel = Number(userInfo.trust_level ?? userInfo.trustLevel ?? -1);
		userInfo.avatar = userInfo.picture ?? userInfo.avatar_url ?? '';
		userInfo.platform = 'nodeloc';

		return await this.saveAndLogin(c, userInfo)
	},

	async githubLogin(c, params) {

		const { code, redirectUri } = params;

		const setting = await settingService.query(c);
		this.assertEnabled(setting, 'githubSwitch');

		const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"Accept": "application/json"
			},
			body: JSON.stringify({
				client_id: setting.githubClientId,
				client_secret: setting.githubClientSecret,
				code: code,
				redirect_uri: redirectUri
			})
		});

		if (!tokenRes.ok) {
			throw new BizError(tokenRes.statusText);
		}

		const token = await tokenRes.json();

		if (token.error) {
			throw new BizError(token.error_description || token.error);
		}

		const userRes = await fetch('https://api.github.com/user', {
			headers: {
				Authorization: 'Bearer ' + token.access_token,
				'User-Agent': 'cloud-mail'
			}
		});

		if (!userRes.ok) {
			throw new BizError(userRes.statusText);
		}

		const userInfo = await userRes.json();

		userInfo.oauthUserId = String(userInfo.id);
		userInfo.username = userInfo.login;
		userInfo.avatar = userInfo.avatar_url;
		userInfo.platform = 'github';
		userInfo.githubCreatedAt = userInfo.created_at;

		return await this.saveAndLogin(c, userInfo);
	},

	async googleLogin(c, params) {

		const { code, redirectUri } = params;

		const setting = await settingService.query(c);
		this.assertEnabled(setting, 'googleSwitch');

		const reqParams = new URLSearchParams()
		reqParams.append('client_id', setting.googleClientId)
		reqParams.append('client_secret', setting.googleClientSecret)
		reqParams.append('code', code)
		reqParams.append('redirect_uri', redirectUri)
		reqParams.append('grant_type', 'authorization_code')

		const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: reqParams.toString()
		});

		if (!tokenRes.ok) {
			throw new BizError(tokenRes.statusText);
		}

		const token = await tokenRes.json();

		const userRes = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
			headers: {
				Authorization: 'Bearer ' + token.access_token
			}
		});

		if (!userRes.ok) {
			throw new BizError(userRes.statusText);
		}

		const userInfo = await userRes.json();

		userInfo.oauthUserId = String(userInfo.sub);
		userInfo.username = userInfo.email;
		userInfo.name = userInfo.name;
		userInfo.avatar = userInfo.picture;
		userInfo.platform = 'google';

		return await this.saveAndLogin(c, userInfo);
	},

	async saveAndLogin(c, userInfo) {

		const githubCreatedAt = userInfo.githubCreatedAt;
		delete userInfo.githubCreatedAt;
		const oauthRow = await this.saveUser(c, userInfo);
		const userRow = await userService.selectByIdIncludeDel(c, oauthRow.userId);

		if (!userRow) {
			const setting = await settingService.query(c);
			if (userInfo.platform === 'github') {
				const amount = Math.max(0, Number(setting.githubMinAgeValue || 0));
				const unitDays = { days: 1, months: 30.4375, years: 365.25, centuries: 36525 };
				const requiredDays = amount * (unitDays[setting.githubMinAgeUnit] || 1);
				if (requiredDays > 0) {
					const createdAt = Date.parse(githubCreatedAt || '');
					if (!Number.isFinite(createdAt)) throw new BizError('无法读取 GitHub 账号注册时间，暂时无法注册');
					if (Date.now() - createdAt < requiredDays * 86400000) throw new BizError(`GitHub 账号注册时间不足，至少需要 ${amount} ${({days:'天',months:'个月',years:'年',centuries:'世纪'})[setting.githubMinAgeUnit] || '天'}`);
				}
			}
			const isNodeLoc = userInfo.platform === 'nodeloc';
			if (isNodeLoc && setting.nodelocRegisterSwitch !== 0) {
				throw new BizError('NodeLoc 新用户注册已关闭');
			}
			const trustLevel = Number(oauthRow.trustLevel ?? -1);
			const trustEnough = !isNodeLoc || trustLevel >= Number(setting.nodelocMinTrustLevel || 0);
			return { userInfo: oauthRow, token: null, needsInvite: isNodeLoc ? (!trustEnough && setting.regKey === 0) : setting.regKey === 0, trustEnough: isNodeLoc ? trustEnough : false };
		}

		const JwtToken = await loginService.login(c, { email: userRow.email, password: null }, true);
		return { userInfo: oauthRow, token: JwtToken };
	},

	async saveUser(c, userInfo) {

		const userInfoRow = await this.getById(c, userInfo.oauthUserId);

		if (!userInfoRow) {
			return await orm(c).insert(oauth).values(userInfo).returning().get();
		} else {
			return await orm(c).update(oauth).set(userInfo).where(eq(oauth.oauthUserId, userInfo.oauthUserId)).returning().get();
		}

	},

	assertEnabled(setting, switchKey) {
		if (setting[switchKey] !== 0) {
			throw new BizError(t('oauthDisabled'));
		}
	},

	async getById(c, oauthUserId) {
		return await orm(c).select().from(oauth).where(eq(oauth.oauthUserId, oauthUserId)).get();
	},

	async deleteByUserId(c, userId) {
		await this.deleteByUserIds(c, [userId]);
	},

	async deleteByUserIds(c, userIds) {
		await orm(c).delete(oauth).where(inArray(oauth.userId, userIds)).run();
	},

	//定时任务凌晨清除未绑定邮箱的oauth用户
	async clearNoBindOathUser(c) {
		await orm(c).delete(oauth).where(eq(oauth.userId, 0)).run();
	},

}

export default  oauthService
