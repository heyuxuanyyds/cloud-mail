import http from '@/axios/index.js';

export function oauthNodeLocLogin(code, redirectUri) {
    return http.post('/oauth/nodeloc/login',{code, redirectUri})
}

export function oauthGithubLogin(code, redirectUri) {
    return http.post('/oauth/github/login',{code, redirectUri})
}

export function oauthGoogleLogin(code, redirectUri) {
    return http.post('/oauth/google/login',{code, redirectUri})
}

export function oauthBindUser(form) {
    return http.put('/oauth/bindUser', form)
}
