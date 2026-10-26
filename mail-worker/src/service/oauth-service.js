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
		const isGithub = oauthRow.platform === 'github';
		const trustLevel = Number(oauthRow.trustLevel ?? -1);
		const minTrust = Number(setting.nodelocMinTrustLevel || 0);
		const noInviteTrust = Math.max(minTrust, Number(setting.nodelocNoInviteTrustLevel || 0));
		const trustEnough = !isNodeLoc || trustLevel >= noInviteTrust;
		if (isNodeLoc && trustLevel < minTrust) throw new BizError(`NodeLoc 账号信任等级不足（当前 NodeLoc 信任等级 ${trustLevel}，最低要求等级 ${minTrust}），无法注册`);
		if (isGithub && !this.githubAgeEnough(oauthRow.githubCreatedAt, setting, 'min')) throw new BizError(this.githubMinAgeMessage(oauthRow.githubCreatedAt, setting));
		if (isNodeLoc && setting.nodelocRegisterSwitch !== 0) {
			throw new BizError('NodeLoc 新用户注册已关闭');
		}
		const githubNoInviteEnough = !isGithub || this.githubAgeEnough(oauthRow.githubCreatedAt, setting, 'noInvite');
		const needsInvite = setting.regKey === 0 && ((isNodeLoc && !trustEnough) || (isGithub && !githubNoInviteEnough));
		if (needsInvite && !code) throw new BizError(isNodeLoc ? `等级不足（当前等级 ${trustLevel}，免邀请码要求等级 ${noInviteTrust}），转为邀请码注册` : this.githubAgeMessage(oauthRow.githubCreatedAt, setting, 'noInvite'));
		const effectivePassword = password || cryptoUtils.genRandomPwd();
		await loginService.register(c, { email, password: effectivePassword, code: needsInvite ? code : '' }, true, { skipRegKey: !needsInvite });

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
		const oauthRow = await this.saveUser(c, userInfo);
		const userRow = await userService.selectByIdIncludeDel(c, oauthRow.userId);

		if (!userRow) {
			const setting = await settingService.query(c);
			const isGithub = userInfo.platform === 'github';
			const isNodeLoc = userInfo.platform === 'nodeloc';
			if (isNodeLoc && setting.nodelocRegisterSwitch !== 0) throw new BizError('NodeLoc 新用户注册已关闭');
			const trustLevel = Number(oauthRow.trustLevel ?? -1);
			const minTrust = Number(setting.nodelocMinTrustLevel || 0);
			const noInviteTrust = Math.max(minTrust, Number(setting.nodelocNoInviteTrustLevel || 0));
			if (isNodeLoc && trustLevel < minTrust) throw new BizError(`NodeLoc 账号信任等级不足（当前 NodeLoc 信任等级 ${trustLevel}，最低要求等级 ${minTrust}），无法注册`);
			if (isGithub && !this.githubAgeEnough(githubCreatedAt, setting, 'min')) throw new BizError(this.githubMinAgeMessage(githubCreatedAt, setting));
			const trustEnough = !isNodeLoc || trustLevel >= noInviteTrust;
			const githubNoInviteEnough = !isGithub || this.githubAgeEnough(githubCreatedAt, setting, 'noInvite');
			const needsInvite = setting.regKey === 0 && ((isNodeLoc && !trustEnough) || (isGithub && !githubNoInviteEnough));
			let notice = '';
			if (needsInvite && isNodeLoc) notice = `NodeLoc 账号信任等级不足（当前 NodeLoc 信任等级 ${trustLevel}，免邀请码要求至少达到等级 ${noInviteTrust}），自动转为邀请码注册`;
			if (needsInvite && isGithub) notice = this.githubAgeMessage(githubCreatedAt, setting, 'noInvite');
			return { userInfo: oauthRow, token: null, needsInvite, trustEnough: isNodeLoc ? trustEnough : true, notice };
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

	githubAgeEnough(createdAtValue, setting, mode = 'min') {
		const unitDays = { days: 1, months: 30.4375, years: 365.25, centuries: 36525 };
		const minAmount = Math.max(0, Number(setting.githubMinAgeValue || 0));
		const minDays = minAmount * (unitDays[setting.githubMinAgeUnit] || 1);
		const noInviteAmount = Math.max(0, Number(setting.githubNoInviteAgeValue ?? setting.githubMinAgeValue ?? 0));
		const noInviteDays = noInviteAmount * (unitDays[setting.githubNoInviteAgeUnit || setting.githubMinAgeUnit] || 1);
		const requiredDays = mode === 'noInvite' ? Math.max(minDays, noInviteDays) : minDays;
		if (requiredDays === 0) return true;
		const createdAt = Date.parse(createdAtValue || '');
		if (!Number.isFinite(createdAt)) return false;
		return Date.now() - createdAt >= requiredDays * 86400000;
	},

	githubAgeMessage(createdAtValue, setting, mode = 'noInvite') {
		const unitDays = { days: 1, months: 30.4375, years: 365.25, centuries: 36525 };
		let amount = Math.max(0, Number(mode === 'noInvite' ? (setting.githubNoInviteAgeValue ?? setting.githubMinAgeValue ?? 0) : (setting.githubMinAgeValue || 0)));
		let unit = mode === 'noInvite' ? (setting.githubNoInviteAgeUnit || setting.githubMinAgeUnit) : setting.githubMinAgeUnit;
		if (mode === 'noInvite') {
			const minDays = Math.max(0, Number(setting.githubMinAgeValue || 0)) * (unitDays[setting.githubMinAgeUnit] || 1);
			if (amount * (unitDays[unit] || 1) < minDays) { amount = Number(setting.githubMinAgeValue || 0); unit = setting.githubMinAgeUnit; }
		}
		const unitLabels = { days: '天', months: '个月', years: '年', centuries: '世纪' };
		const createdAt = Date.parse(createdAtValue || '');
		const currentAgeDays = Number.isFinite(createdAt) ? Math.max(0, Math.floor((Date.now() - createdAt) / 86400000)) : '未知';
		return `GitHub 账号注册时长不足（当前 GitHub 账号已注册 ${currentAgeDays}${currentAgeDays === '未知' ? '' : '天'}，免邀请码要求至少 ${amount}${unitLabels[unit] || '天'}），自动转为邀请码注册`;
	},

	githubMinAgeMessage(createdAtValue, setting) {
		const amount = Math.max(0, Number(setting.githubMinAgeValue || 0));
		const unitLabels = { days: '天', months: '个月', years: '年', centuries: '世纪' };
		const createdAt = Date.parse(createdAtValue || '');
		const currentAgeDays = Number.isFinite(createdAt) ? Math.max(0, Math.floor((Date.now() - createdAt) / 86400000)) : '未知';
		return `GitHub 账号注册时长不足（当前 GitHub 账号已注册 ${currentAgeDays}${currentAgeDays === '未知' ? '' : '天'}，最低要求至少 ${amount}${unitLabels[setting.githubMinAgeUnit] || '天'}），无法注册`;
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
