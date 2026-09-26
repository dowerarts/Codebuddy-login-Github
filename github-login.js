const axios = require('axios');
const { HttpsProxyAgent } = require('https-proxy-agent');
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const crypto = require('crypto');
const { TOTP } = require('totp-generator');

function isDataImpulseHost(host) {
    if (!host) return false;
    const h = String(host).toLowerCase();
    return /dataimpulse/.test(h) || /gw\.dataimpulse\.com/.test(h);
}

function loadProxyPool() {
    const jsonFile = path.join(__dirname, 'configgithublogin.json');
    if (fs.existsSync(jsonFile)) {
        try {
            const cfg = JSON.parse(fs.readFileSync(jsonFile, 'utf8'));
            if (cfg.proxy) {
                if (Array.isArray(cfg.proxy)) {
                    return cfg.proxy.map((s) => String(s).trim()).filter(Boolean);
                }
                if (typeof cfg.proxy === 'string' && cfg.proxy.trim()) {
                    return [cfg.proxy.trim()];
                }
            }
        } catch (e) {
            console.error('Gagal membaca proxy dari configgithublogin.json:', e.message);
        }
    }

    const file = path.join(__dirname, 'proxy.txt');
    if (!fs.existsSync(file)) return [];
    return fs.readFileSync(file, 'utf8')
        .split(/[\r\n]+/)
        .map((s) => s.trim())
        .filter(Boolean);
}

function randomSessionProxy(proxyUrl) {
    if (!proxyUrl) return proxyUrl;
    const m = proxyUrl.match(/^https?:\/\/([^@/]*)@([^:/]+):(\d+)$/);
    if (!m) return proxyUrl;

    const host = m[2];
    if (!isDataImpulseHost(host)) return proxyUrl;

    let userPlain = m[1];
    try { userPlain = decodeURIComponent(userPlain); } catch {  }

    const sep = userPlain.lastIndexOf(':');
    if (sep <= 0) return proxyUrl;

    const userPart = userPlain.slice(0, sep);
    const passPart = userPlain.slice(sep + 1);
    const rand = Math.random().toString(36).slice(2, 10) + Date.now().toString(36).slice(-4);
    const tag = /;sessid\./i.test(userPart)
        ? userPart.replace(/;sessid\.[^;]*/i, `;sessid.${rand}`)
        : `${userPart};sessid.${rand}`;

    const enc = (v) => encodeURIComponent(String(v)).replace(/%3B/gi, ';');
    return `http://${enc(tag)}:${enc(passPart)}@${host}:${m[3]}`;
}

function buildStickyProxy() {
    const pool = loadProxyPool();
    if (!pool.length) {
        throw new Error('Tidak ada proxy di configgithublogin.json atau proxy.txt. Setiap user wajib membawa proxy sendiri.');
    }
    const base = pool[Math.floor(Math.random() * pool.length)];
    return randomSessionProxy(base);
}

const proxyValidationCache = new Map();

async function validateProxy(proxyUrl) {
    const parsed = parseProxy(proxyUrl);
    if (!parsed) return { ok: false, reason: 'format proxy tidak valid' };
    
    const baseKey = `${parsed.username || ''}:${parsed.password || ''}@${parsed.host}:${parsed.port}`;
    if (proxyValidationCache.has(baseKey)) return proxyValidationCache.get(baseKey);

    try {
        const res = await axios.get('https://github.com/', {
            httpsAgent: new HttpsProxyAgent(proxyUrl),
            httpAgent: new HttpsProxyAgent(proxyUrl),
            timeout: 8000,
            maxRedirects: 0,
            validateStatus: () => true,
            headers: { 'User-Agent': CONFIG.userAgent, Accept: '*/*' },
        });
        const result = res.status === 200
            ? { ok: true }
            : { ok: false, reason: res.status === 407 ? '407 Proxy Authentication Required — kredensial proxy salah' : `status ${res.status}` };
        proxyValidationCache.set(baseKey, result);
        return result;
    } catch (e) {
        const result = { ok: false, reason: e.message || 'connection error' };
        proxyValidationCache.set(baseKey, result);
        return result;
    }
}

const USER_AGENT_POOL = [
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
];

function pickUserAgent() {
    return USER_AGENT_POOL[Math.floor(Math.random() * USER_AGENT_POOL.length)];
}

function platformFromUA(ua) {
    if (/Mac/.test(ua)) return '"macOS"';
    if (/Windows/.test(ua)) return '"Windows"';
    if (/Linux/.test(ua)) return '"Linux"';
    return '"macOS"';
}

function loadDeviceTokenPool() {
    const file = path.join(__dirname, 'device_tokens.txt');
    if (!fs.existsSync(file)) return [];
    return fs.readFileSync(file, 'utf8')
        .split(/[\r\n]+/)
        .map((s) => s.trim())
        .filter((s) => s.length > 10);
}

const DEVICE_TOKEN_POOL = loadDeviceTokenPool();
function pickDeviceToken() {
    if (DEVICE_TOKEN_POOL.length) {
        return DEVICE_TOKEN_POOL[Math.floor(Math.random() * DEVICE_TOKEN_POOL.length)];
    }
    
    
    
    return generateCbDeviceToken();
}

function generateCbDeviceToken() {
    const part1 = crypto.randomBytes(180).toString('base64');
    const part2 = crypto.randomBytes(180).toString('base64');
    return `v3:${part1}#0#${part2}`;
}

function parseProxy(proxyStr) {
    if (!proxyStr) return null;
    try {
        const url = new URL(proxyStr);
        return {
            type: url.protocol.replace(':', '') || 'http',
            host: url.hostname,
            port: parseInt(url.port, 10),
            username: url.username || undefined,
            password: url.password || undefined,
            server: proxyStr,
        };
    } catch (e) {
        const parts = proxyStr.split(':');
        if (parts.length >= 4) {
            return {
                type: 'http',
                host: parts[0],
                port: parseInt(parts[1], 10),
                username: parts[2],
                password: parts[3],
                server: `http://${parts[0]}:${parts[1]}`,
            };
        }
    }
    return null;
}

function askQuestion(query) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    return new Promise((resolve) => rl.question(query, (ans) => {
        rl.close();
        resolve(ans.trim());
    }));
}

const COLOR = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    cyan: '\x1b[36m',
    white: '\x1b[37m',
    gray: '\x1b[90m',
};

function now() {
    return new Date().toLocaleTimeString('id-ID', { hour12: false });
}

function log(step, text, type = 'info') {
    const icons = { info: '[i]', success: '[+]', warn: '[!]', error: '[x]', fatal: '[!!]', request: '[>]', cookie: '[c]', wait: '[~]' };
    const colors = { info: COLOR.white, success: COLOR.green, warn: COLOR.yellow, error: COLOR.red, fatal: COLOR.magenta, request: COLOR.blue, cookie: COLOR.yellow, wait: COLOR.gray };
    console.log(`${COLOR.gray}[${now()}]${COLOR.reset} ${colors[type] || COLOR.white}${icons[type] || '*'}${COLOR.reset} ${COLOR.cyan}[${step}]${COLOR.reset} ${colors[type] || COLOR.white}${text}${COLOR.reset}`);
}

function logCookies(step, setCookieHeader, title) {
    const arr = Array.isArray(setCookieHeader) ? setCookieHeader : (setCookieHeader ? [setCookieHeader] : []);
    const names = arr.map(c => {
        const m = c.match(/^([^=]+)=/);
        return m ? m[1] : c;
    }).filter(Boolean);
    log(step, `${title || 'Cookies'}: ${names.join(', ') || 'none'}`, 'cookie');
}

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function extractCookies(setCookieHeader) {
    const cookies = {};
    if (!setCookieHeader) return cookies;
    const arr = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
    for (const c of arr) {
        const match = c.match(/^([^=]+)=([^;]+)/);
        if (match) cookies[match[1]] = match[2];
    }
    return cookies;
}

function buildCookieString(cookies) {
    return Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ');
}

function mergeCookies(cookies, setCookieHeader) {
    const newCookies = extractCookies(setCookieHeader);
    for (const [k, v] of Object.entries(newCookies)) {
        if (v === '' || v === '""') { delete cookies[k]; continue; }
        cookies[k] = v;
    }
    return cookies;
}

function mergeCookiesKeep(cookies, setCookieHeader) {
    const newCookies = extractCookies(setCookieHeader);
    for (const [k, v] of Object.entries(newCookies)) {
        if (v === '' || v === '""') continue;
        cookies[k] = v;
    }
    return cookies;
}

function extractAuthenticityToken(html) {
    const match = html.match(/<input[^>]*name="authenticity_token"[^>]*value="([^"]+)"/i);
    return match ? match[1] : null;
}

async function resolveTwoFaCode(twoFaInput) {
    
    if (/^\d{6}$/.test(twoFaInput)) return twoFaInput;
    
    if (/^[A-Za-z2-7]{16,64}$/.test(twoFaInput)) {
        const { otp } = await TOTP.generate(twoFaInput, { explicitZeroPad: true });
        return otp;
    }
    return twoFaInput;
}

function loadConfigFile() {
    const file = path.join(__dirname, 'configgithublogin.json');
    if (!fs.existsSync(file)) return {};
    try {
        return JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (e) {
        console.error('Gagal membaca configgithublogin.json:', e.message);
        return {};
    }
}

const JSON_CONFIG = loadConfigFile();

function pickConfig(key, envKey, defaultValue) {
    if (process.env[envKey] !== undefined) return process.env[envKey];
    if (JSON_CONFIG[key] !== undefined && JSON_CONFIG[key] !== '') return JSON_CONFIG[key];
    return defaultValue;
}

const CONFIG = {
    proxy: pickConfig('proxy', 'PROXY', buildStickyProxy()),
    userAgent: process.env.USER_AGENT || pickUserAgent(),
    octo: process.env.OCTO || 'GH1.1.1305789960.1790215790',
    cbDeviceToken: process.env.CB_DEVICE_TOKEN || pickDeviceToken(),
    concurrency: Math.max(1, Math.min(parseInt(pickConfig('concurrency', 'CONCURRENCY', '1'), 10), 10)),
    delayMs: Math.max(0, parseInt(pickConfig('delayMs', 'DELAY_MS', '10000'), 10)),
};

function buildCommonHeaders() {
    return {
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Ch-Ua': '"Chromium";v="151", "Not=A?Brand";v="99"',
        'Sec-Ch-Ua-Mobile': '?0',
        'Sec-Ch-Ua-Platform': platformFromUA(CONFIG.userAgent),
    };
}

function buildAxiosConfig(extraHeaders = {}, cookie = '', useProxy = true) {
    const proxyParsed = parseProxy(CONFIG.proxy);
    const headers = { ...buildCommonHeaders(), 'User-Agent': CONFIG.userAgent, ...extraHeaders };
    if (cookie) headers.Cookie = cookie;

    const config = {
        headers,
        timeout: 30000,
        maxRedirects: 0,
        validateStatus: () => true,
        decompress: true,
    };

    if (proxyParsed && useProxy) {
        config.httpsAgent = new HttpsProxyAgent(CONFIG.proxy);
        config.httpAgent = new HttpsProxyAgent(CONFIG.proxy);
    }

    return config;
}

async function followRedirect(url, referer, cookies) {
    let currentUrl = url;
    let redirectCount = 0;
    while (redirectCount < 5) {
        const res = await axios.get(
            currentUrl,
            buildAxiosConfig({
                Host: 'github.com',
                Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-User': '?1',
                'Sec-Fetch-Dest': 'document',
                Referer: referer,
                Priority: 'u=0, i',
            }, buildCookieString(cookies))
        );

        const newCookies = extractCookies(res.headers['set-cookie']);
        if (newCookies._gh_sess) cookies._gh_sess = newCookies._gh_sess;
        if (newCookies.datadome) cookies.datadome = newCookies.datadome;
        if (newCookies.logged_in) cookies.logged_in = newCookies.logged_in;

        if (res.status !== 302 || !res.headers['location']) {
            return res;
        }
        currentUrl = res.headers['location'].startsWith('http') ? res.headers['location'] : `https://github.com${res.headers['location']}`;
        referer = currentUrl;
        redirectCount++;
    }
    throw new Error('Too many redirects');
}

async function loginGitHub(email, password, twoFa, outDir = process.cwd()) {
    const cookies = { _octo: CONFIG.octo };

    const homeUrl = 'https://github.com/';
    const loginUrl = 'https://github.com/login';
    const sessionUrl = 'https://github.com/session';

    log('Step 1', `GET ${homeUrl}`, 'request');
    const homeRes = await axios.get(homeUrl, buildAxiosConfig({
        Host: 'github.com',
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1',
        'Sec-Fetch-Dest': 'document',
        Priority: 'u=0, i',
    }, buildCookieString(cookies)));

    log('Step 1', `Status: ${homeRes.status}`, homeRes.status === 200 ? 'success' : 'warn');
    mergeCookies(cookies, homeRes.headers['set-cookie']);
    logCookies('Step 1', homeRes.headers['set-cookie'], 'Set-Cookie');

    await sleep(500 + Math.floor(Math.random() * 1000));

    log('Step 2', `GET ${loginUrl}`, 'request');
    const loginGetRes = await axios.get(loginUrl, buildAxiosConfig({
        Host: 'github.com',
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1',
        'Sec-Fetch-Dest': 'document',
        Referer: homeUrl,
        Priority: 'u=0, i',
    }, buildCookieString(cookies)));

    log('Step 2', `Status: ${loginGetRes.status}`, loginGetRes.status === 200 ? 'success' : 'warn');
    mergeCookies(cookies, loginGetRes.headers['set-cookie']);
    logCookies('Step 2', loginGetRes.headers['set-cookie'], 'Set-Cookie');

    const authenticityToken = extractAuthenticityToken(loginGetRes.data);
    if (!authenticityToken) {
        log('Step 2', 'authenticity_token tidak ditemukan', 'error');
        return false;
    }
    log('Step 2', `authenticity_token: ${COLOR.gray}${authenticityToken}${COLOR.reset}`, 'info');

    const timestamp = Date.now();
    const timestampSecretMatch = loginGetRes.data.match(/name="timestamp_secret"[^>]*value="([^"]+)"/i);
    const requiredFieldMatch = loginGetRes.data.match(/name="required_field_([a-zA-Z0-9]+)"/i);
    const requiredFieldName = requiredFieldMatch ? `required_field_${requiredFieldMatch[1]}` : 'required_field_c9a7';

    const loginPayload = new URLSearchParams();
    loginPayload.set('commit', 'Sign+in');
    loginPayload.set('authenticity_token', authenticityToken);
    loginPayload.set('add_account', '');
    loginPayload.set('login', email);
    loginPayload.set('password', password);
    loginPayload.set('webauthn-conditional', 'undefined');
    loginPayload.set('javascript-support', 'true');
    loginPayload.set('webauthn-support', 'supported');
    loginPayload.set('webauthn-iuvpaa-support', 'supported');
    loginPayload.set('return_to', 'https://github.com/login');
    loginPayload.set('allow_signup', '');
    loginPayload.set('client_id', '');
    loginPayload.set('integration', '');
    loginPayload.set(requiredFieldName, '');
    loginPayload.set('timestamp', String(timestamp));
    loginPayload.set('timestamp_secret', timestampSecretMatch ? timestampSecretMatch[1] : '');

    await sleep(500 + Math.floor(Math.random() * 1000));

    log('Step 3', `POST ${sessionUrl}`, 'request');
    const loginPostRes = await axios.post(
        sessionUrl,
        loginPayload.toString(),
        buildAxiosConfig({
            Host: 'github.com',
            'Cache-Control': 'max-age=0',
            'Content-Type': 'application/x-www-form-urlencoded',
            Origin: 'https://github.com',
            Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            Referer: loginUrl,
            Priority: 'u=0, i',
        }, buildCookieString(cookies))
    );

    log('Step 3', `Status: ${loginPostRes.status}`, loginPostRes.status === 302 ? 'success' : 'warn');
    log('Step 3', `Location: ${loginPostRes.headers['location'] || 'none'}`);
    logCookies('Step 3', loginPostRes.headers['set-cookie'], 'Set-Cookie');

    mergeCookies(cookies, loginPostRes.headers['set-cookie']);

    if (loginPostRes.status === 302 && loginPostRes.headers['location']) {
        const location = loginPostRes.headers['location'];
        const redirectTarget = location.startsWith('http') ? location : `https://github.com${location}`;

        
        
        if (location.includes('/suspended')) {
            log('Login', 'AKUN SUSPENDED -- akses di-blokir karena pelanggaran Terms of Service', 'fatal');
            log('Login', '   Pesan GitHub: "Access to your account has been suspended due to a violation of our Terms of Service."', 'error');
            log('Login', '   Solusi: hubungi GitHub Support atau ganti akun lain.', 'warn');
            return { isLoggedIn: false, cookies };
        }

        
        if (location.includes('/sessions/two-factor')) {
            log('Step 4', '2FA required -- mengambil halaman two-factor', 'warn');

            const twoFaRes = await followRedirect(redirectTarget, sessionUrl, cookies);
            log('Step 4', `2FA page status: ${twoFaRes.status}`, twoFaRes.status === 200 ? 'success' : 'warn');
            fs.writeFileSync('login_redirect.html', twoFaRes.data);

            const twoFaPageUrl = twoFaRes.request && twoFaRes.request.res && twoFaRes.request.res.responseUrl
                ? twoFaRes.request.res.responseUrl
                : redirectTarget;

            
            const formMatch = twoFaRes.data.match(/<form[^>]*action="\/sessions\/two-factor"[^>]*>([\s\S]*?)<\/form>/i);
            let twoFaToken = formMatch ? extractAuthenticityToken(formMatch[1]) : null;
            if (!twoFaToken) twoFaToken = extractAuthenticityToken(twoFaRes.data);

            if (!twoFaToken) {
                log('Step 4', 'authenticity_token form 2FA tidak ditemukan', 'error');
                return false;
            }
            log('Step 4', `2FA authenticity_token: ${COLOR.gray}${twoFaToken}${COLOR.reset}`, 'info');

            
            let otpCode;
            try {
                otpCode = await resolveTwoFaCode(twoFa);
            } catch (e) {
                log('Step 5', `Gagal generate TOTP: ${e.message}`, 'error');
                otpCode = twoFa;
            }
            log('Step 5', `app_otp: ${COLOR.gray}${otpCode}${COLOR.reset}`, 'info');

            await sleep(500 + Math.floor(Math.random() * 800));

            const twoFaPayload = new URLSearchParams();
            twoFaPayload.set('authenticity_token', twoFaToken);
            twoFaPayload.set('app_otp', otpCode);
            twoFaPayload.set('commit', 'Verify');

            log('Step 5', 'POST https://github.com/sessions/two-factor', 'request');
            const twoFaPostRes = await axios.post(
                'https://github.com/sessions/two-factor',
                twoFaPayload.toString(),
                buildAxiosConfig({
                    Host: 'github.com',
                    'Cache-Control': 'max-age=0',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    Origin: 'https://github.com',
                    Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'Sec-Fetch-Site': 'same-origin',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-User': '?1',
                    'Sec-Fetch-Dest': 'document',
                    Referer: 'https://github.com/sessions/two-factor/app',
                    Priority: 'u=0, i',
                }, buildCookieString(cookies))
            );

            log('Step 5', `Status: ${twoFaPostRes.status}`, twoFaPostRes.status === 302 ? 'success' : 'warn');
            log('Step 5', `Location: ${twoFaPostRes.headers['location'] || 'none'}`);

            mergeCookies(cookies, twoFaPostRes.headers['set-cookie']);
            logCookies('Step 5', twoFaPostRes.headers['set-cookie'], 'Set-Cookie');

            if (twoFaPostRes.status === 302 && twoFaPostRes.headers['location']) {
                const finalRes = await followRedirect(
                    twoFaPostRes.headers['location'].startsWith('http') ? twoFaPostRes.headers['location'] : `https://github.com${twoFaPostRes.headers['location']}`,
                    'https://github.com/sessions/two-factor',
                    cookies
                );
                mergeCookies(cookies, finalRes.headers['set-cookie']);
                log('Step 6', `Final redirect status: ${finalRes.status}`, finalRes.status === 200 ? 'success' : 'warn');
                fs.writeFileSync('login_redirect.html', finalRes.data);
            } else if (twoFaPostRes.status === 200) {
                
                fs.writeFileSync('login_redirect.html', twoFaPostRes.data);
                const errMatch = twoFaPostRes.data.match(/flash-error[\s\S]{0,300}/i);
                log('Step 5', `2FA gagal: ${errMatch ? errMatch[0].substring(0, 150) : 'kode OTP ditolak'}`, 'error');
            }
        } else {
            const redirectRes = await followRedirect(
                redirectTarget,
                sessionUrl,
                cookies
            );
            mergeCookies(cookies, redirectRes.headers['set-cookie']);
            log('Step 4', `Final redirect status: ${redirectRes.status}`, redirectRes.status === 200 ? 'success' : 'warn');

            fs.writeFileSync('login_redirect.html', redirectRes.data);
            log('Step 4', 'Saved login_redirect.html', 'info');
        }
    }

    const isLoggedIn = cookies.logged_in === 'yes' || (loginPostRes.headers['location'] || '').includes('/dashboard');
    if (isLoggedIn) {
        log('Login', `Login berhasil untuk ${COLOR.gray}${email}${COLOR.reset}`, 'success');
        fs.mkdirSync(outDir, { recursive: true });
        fs.writeFileSync(path.join(outDir, 'github_login_session.json'), JSON.stringify({ email, cookies, createdAt: new Date().toISOString() }, null, 2));
        log('Login', `Session saved to ${path.join(outDir, 'github_login_session.json')}`, 'cookie');

        const cookieString = buildCookieString(cookies);
        log('Login', `GitHub cookie string tersimpan (${cookieString.length} chars)`, 'cookie');
    } else {
        log('Login', 'Login gagal atau akun memerlukan verifikasi tambahan', 'error');
    }

    return { isLoggedIn, cookies };
}

function randomState(length = 32) {
    const chars = 'abcdef0123456789';
    let out = '';
    for (let i = 0; i < length; i++) out += chars[Math.floor(Math.random() * chars.length)];
    return out;
}

function buildCbApiHeaders(referer = 'https://www.codebuddy.ai/home') {
    return {
        Host: 'www.codebuddy.ai',
        'Sec-Ch-Ua-Platform': platformFromUA(CONFIG.userAgent),
        'Accept-Language': 'id-ID,id;q=0.9',
        'Sec-Ch-Ua': '"Chromium";v="151", "Not=A?Brand";v="99"',
        'Sec-Ch-Ua-Mobile': '?0',
        'X-Device-Token': CONFIG.cbDeviceToken,
        'X-Domain': 'www.codebuddy.ai',
        'X-Requested-With': 'XMLHttpRequest',
        'User-Agent': CONFIG.userAgent,
        Accept: 'application/json, text/plain, */*',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        Referer: referer,
        'Accept-Encoding': 'gzip, deflate, br',
        Priority: 'u=1, i',
    };
}

async function loginCodebuddy(ghCookies, email, outDir = process.cwd()) {
    
    const cbCookies = {};

    
    
    const CB_HEADERS = {
        Host: 'www.codebuddy.ai',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Dest': 'iframe',
        'Accept-Encoding': 'gzip, deflate, br',
        Priority: 'u=0, i',
    };

    
    function parseOAuthParams(url) {
        try {
            const u = new URL(url);
            return {
                state: u.searchParams.get('state') || '',
                sessionState: u.searchParams.get('session_state') || '',
                code: u.searchParams.get('code') || '',
            };
        } catch (e) {
            return { state: '', sessionState: '', code: '' };
        }
    }

    
    
    
    
    const cbLoginSelect = `https://www.codebuddy.ai/login/select?redirect_uri=https%3A%2F%2Fwww.codebuddy.ai%2Fhome`;
    const cbRegisterComplete = `https://www.codebuddy.ai/login/select?redirect_uri=https%3A%2F%2Fwww.codebuddy.ai%2Fregister%2Fuser%2Fcomplete`;
    const cbAuthUrl = `https://www.codebuddy.ai/auth/realms/copilot/protocol/openid-connect/auth?client_id=console&response_type=code&redirect_uri=https%3A%2F%2Fwww.codebuddy.ai%2Flogin%2Fselect%3Fredirect_uri%3Dhttps%253A%252F%252Fwww.codebuddy.ai%252Fhome&v=2210&product=codebuddy`;
    const cbAccountsAuthUrl = `https://www.codebuddy.ai/auth/realms/copilot/protocol/openid-connect/auth?client_id=console&redirect_uri=https%3A%2F%2Fwww.codebuddy.ai%2Fconsole%2Faccounts%2F.apisix%2Fredirect&state=${randomState(32)}&response_type=code&scope=openid%20offline_access`;

    
    const cbConsoleReferer = `https://www.codebuddy.ai/auth/realms/copilot/protocol/openid-connect/auth?client_id=console&redirect_uri=https%3A%2F%2Fwww.codebuddy.ai%2Fconsole%2Faccounts%2F.apisix%2Fredirect&state=${randomState(32)}&response_type=code&scope=openid%20offline_access`;

    
    const cbAccountsUrl = 'https://www.codebuddy.ai/console/accounts';

    
    
    
    
    log('CB-0pre', 'POST /console/auth/risk-context (awal)', 'request');
    try {
        const preRisk = await axios.post('https://www.codebuddy.ai/console/auth/risk-context', '', buildAxiosConfig(
            buildCbApiHeaders('https://www.codebuddy.ai/'),
            buildCookieString(cbCookies),
            true
        ));
        mergeCookiesKeep(cbCookies, preRisk.headers['set-cookie']);
        log('CB-0pre', `Status: ${preRisk.status}`, preRisk.status === 200 ? 'success' : 'warn');
    } catch (e) {
        log('CB-0pre', `Skip: ${e.message}`, 'warn');
    }

    
    
    log('CB-0a', 'GET /console/accounts (anonymous, no session)', 'request');
    const res0a = await axios.get('https://www.codebuddy.ai/console/accounts', buildAxiosConfig(
        buildCbApiHeaders('https://www.codebuddy.ai/home'),
        buildCookieString(cbCookies),
        true
    ));
    log('CB-0a', `Status: ${res0a.status}`, res0a.status === 302 ? 'success' : 'warn');
    logCookies('CB-0a', res0a.headers['set-cookie'], 'Set-Cookie');
    mergeCookies(cbCookies, res0a.headers['set-cookie']);
    const firstSession = cbCookies.session || null;
    if (!firstSession) {
        log('CB-0a', 'Cookie session pertama tidak didapat', 'error');
        return { ok: false, reason: 'no-first-session' };
    }

    
    
    log('CB-0b', 'GET /console/accounts (dengan session pertama)', 'request');
    const res0b = await axios.get('https://www.codebuddy.ai/console/accounts', buildAxiosConfig(
        buildCbApiHeaders(cbRegisterComplete),
        buildCookieString(cbCookies),
        true
    ));
    log('CB-0b', `Status: ${res0b.status}`, res0b.status === 302 ? 'success' : 'warn');
    logCookies('CB-0b', res0b.headers['set-cookie'], 'Set-Cookie');
    mergeCookies(cbCookies, res0b.headers['set-cookie']);
    if (!cbCookies.session) {
        log('CB-0b', 'Cookie session kedua tidak didapat', 'error');
        return { ok: false, reason: 'no-second-session' };
    }

    
    const baseCookies = {
        _gcl_au: '1.1.934137743.1790392913',
        qcloud_visitId: 'd61de927f5b3accc645488530dbd4788',
        sajssdk_2015_cross_new_user: '1',
        qcloud_from: 'qcloud.outside.seo-1790392914500',
        qcloud_outsite_refer: 'https://www.codebuddy.ai/login/select?redirect_uri=https%253A%252F%252Fwww.codebuddy.ai%252Fhome&session_sta',
        '397f1c3795037d16': '4sTZfSQuLLe69rDOZGHg6P7TIAXobjHQ8JnxZnY6v%2BFQjxrawKgqTKAQxj86ysphKReswImFsuU3vjl6rsyyfDzCoeQmedaPU40j6VwkA64cN6a3w1Fgx5zaDKzmHcXeG0xrNe81au%2BC1k%2FlA%2FS0OWnodtDCPH8Bnb2ipBFc95ukctBegvf9i9NDnkaLz%2Fhu',
        _TDID_CK: '1790392953949',
    };
    for (const [k, v] of Object.entries(baseCookies)) {
        if (!cbCookies[k]) cbCookies[k] = v;
    }

    
    
    log('CB-0c', 'GET /login/select (risk-state)', 'request');
    try {
        const selectRes = await axios.get(cbLoginSelect, buildAxiosConfig({
            Host: 'www.codebuddy.ai',
            Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Dest': 'document',
            Referer: cbRegisterComplete,
        }, buildCookieString(cbCookies), true));
        mergeCookies(cbCookies, selectRes.headers['set-cookie']);
        log('CB-0c', `Status: ${selectRes.status}`, selectRes.status === 200 ? 'success' : 'warn');
        logCookies('CB-0c', selectRes.headers['set-cookie'], 'Set-Cookie');
    } catch (e) {
        log('CB-0c', `Skip: ${e.message}`, 'warn');
    }

    
    const kcRestartBackup = cbCookies.KC_RESTART || null;
    const authSessionBackup = cbCookies.AUTH_SESSION_ID || null;

    
    log('CB-1', `GET codebuddy auth page`, 'request');
    const res1 = await axios.get(cbAuthUrl, buildAxiosConfig({
        ...CB_HEADERS,
        Referer: cbLoginSelect,
    }, buildCookieString(cbCookies), true));
    log('CB-1', `Status: ${res1.status}`, res1.status === 200 ? 'success' : 'warn');
    mergeCookies(cbCookies, res1.headers['set-cookie']);
    logCookies('CB-1', res1.headers['set-cookie'], 'Set-Cookie');
    if (res1.status !== 200) return { ok: false, reason: `auth page status ${res1.status}` };

    
    let rawHref = null;
    const ghIdPatterns = [
        /<a[^>]*id="social-github"[^>]*href="([^"]+)"/i,
        /<a[^>]*href="([^"]+)"[^>]*id="social-github"[^>]*>/i,
        /href="(\/auth\/realms\/copilot\/broker\/github\/login\?[^"]+)"/i,
    ];
    for (const p of ghIdPatterns) {
        const m = res1.data.match(p);
        if (m) { rawHref = m[1]; break; }
    }
    if (!rawHref) {
        log('CB-2', 'Tombol #social-github tidak ditemukan', 'error');
        return { ok: false, reason: 'social-github button not found' };
    }
    const brokerPath = rawHref.replace(/&amp;/g, '&');
    log('CB-2', `GitHub broker path: ${COLOR.gray}${brokerPath.slice(0, 80)}...${COLOR.reset}`, 'success');

    
    
    let cbTabId = '';
    try {
        const brokerUrlObj = new URL(`https://www.codebuddy.ai${brokerPath}`);
        cbTabId = brokerUrlObj.searchParams.get('tab_id') || '';
    } catch (e) {  }

    await sleep(400 + Math.floor(Math.random() * 600));

    
    const brokerUrl = `https://www.codebuddy.ai${brokerPath}`;
    log('CB-3', `GET broker github/login`, 'request');
    const res3 = await axios.get(brokerUrl, buildAxiosConfig({
        ...CB_HEADERS,
        Referer: cbAuthUrl,
    }, buildCookieString(cbCookies), true));
    log('CB-3', `Status: ${res3.status}`, res3.status === 302 || res3.status === 303 ? 'success' : 'warn');
    const location = res3.headers['location'];
    log('CB-3', `Location: ${location ? location.slice(0, 110) : 'none'}`);
    mergeCookies(cbCookies, res3.headers['set-cookie']);
    if (!location) {
        log('CB-3', 'Tidak ada Location dari broker', 'error');
        return { ok: false, reason: 'no redirect from broker' };
    }

    await sleep(400 + Math.floor(Math.random() * 600));

    
    const ghAuthUrl = location.startsWith('http') ? location : `https://github.com${location}`;
    log('CB-4', `GET github.com/login/oauth/authorize`, 'request');

    const res4 = await axios.get(ghAuthUrl, buildAxiosConfig({
        Host: 'github.com',
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Sec-Fetch-Site': 'cross-site',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1',
        'Sec-Fetch-Dest': 'document',
        Referer: cbAuthUrl,
        'Accept-Encoding': 'gzip, deflate, br',
        Priority: 'u=0, i',
    }, buildCookieString(ghCookies)));
    log('CB-4', `Status: ${res4.status}`, res4.status === 302 ? 'success' : 'warn');
    log('CB-4', `Location: ${res4.headers['location'] || 'none'}`);

    
    const ghSet = extractCookies(res4.headers['set-cookie']);
    for (const [k, v] of Object.entries(ghSet)) if (v) ghCookies[k] = v;

    let ghRedirect = res4.headers['location'] || null;

    
    
    if (res4.status === 302 && ghRedirect) {
        log('CB-4', 'Akun sudah authorized, redirect langsung ke codebuddy', 'success');
    } else if (res4.status === 200) {
        
        const body4 = typeof res4.data === 'string' ? res4.data : '';

        
        if (/This account is flagged/i.test(body4)) {
            log('CB-4', 'AKUN FLAGGED -- tidak bisa authorize OAuth ke pihak ketiga', 'fatal');
            log('CB-4', '   GitHub: "This account is flagged, and therefore cannot authorize a third party application."', 'error');
            log('CB-4', '   Solusi: pakai akun lain atau ajukan review ke GitHub Support.', 'warn');
            return { ok: false, reason: 'account-flagged', flagged: true };
        }

        
        const formMatch = body4.match(/<form[^>]*action="\/login\/oauth\/authorize"[^>]*>([\s\S]*?)<\/form>/i);
        const consentToken = formMatch ? extractAuthenticityToken(formMatch[1]) : extractAuthenticityToken(body4);
        if (!consentToken) {
            log('CB-4', 'Halaman authorize tanpa form consent -- tidak bisa lanjut', 'error');
            fs.writeFileSync('cb_authorize_debug.html', body4);
            return { ok: false, reason: 'authorize form not found' };
        }
        log('CB-4', `Consent form ditemukan, token: ${COLOR.gray}${consentToken.slice(0, 25)}...${COLOR.reset}`, 'success');

        
        const authUrlObj = new URL(ghAuthUrl);
        const stateParam = authUrlObj.searchParams.get('state') || '';
        const clientIdParam = authUrlObj.searchParams.get('client_id') || '';
        const redirectUriParam = authUrlObj.searchParams.get('redirect_uri') || '';

        const consentPayload = new URLSearchParams();
        consentPayload.set('authorize', '1');
        consentPayload.set('authenticity_token', consentToken);
        consentPayload.set('redirect_uri_specified', 'true');
        consentPayload.set('client_id', clientIdParam);
        consentPayload.set('redirect_uri', redirectUriParam);
        consentPayload.set('state', stateParam);
        consentPayload.set('integration_version_number', '2');
        consentPayload.set('authorize', '1');

        await sleep(1000 + Math.floor(Math.random() * 1000));

        log('CB-4b', 'POST /login/oauth/authorize (approve consent)', 'request');
        const consentRes = await axios.post(
            'https://github.com/login/oauth/authorize',
            consentPayload.toString(),
            buildAxiosConfig({
                Host: 'github.com',
                'Cache-Control': 'max-age=0',
                'Sec-Ch-Device-Memory': '16',
                'Sec-Ch-Ua-Arch': '""',
                'Sec-Ch-Ua-Model': '""',
                'Sec-Ch-Ua-Full-Version-List': '',
                'Upgrade-Insecure-Requests': '1',
                'Content-Type': 'application/x-www-form-urlencoded',
                Origin: 'https://github.com',
                Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-User': '?1',
                'Sec-Fetch-Dest': 'document',
                Referer: ghAuthUrl,
                Priority: 'u=0, i',
            }, buildCookieString(ghCookies))
        );
        log('CB-4b', `Status: ${consentRes.status}`, consentRes.status === 200 ? 'success' : 'warn');

        const ghSet2 = extractCookies(consentRes.headers['set-cookie']);
        for (const [k, v] of Object.entries(ghSet2)) if (v) ghCookies[k] = v;

        if (consentRes.headers['location']) {
            ghRedirect = consentRes.headers['location'];
        } else {
            
            const cBody = typeof consentRes.data === 'string' ? consentRes.data : '';
            const authorized = /OAuth application authorized/i.test(cBody);
            const refreshMatch = cBody.match(/http-equiv="refresh" content="0;url=([^"]+)"/i);
            if (refreshMatch) {
                ghRedirect = refreshMatch[1].replace(/&amp;/g, '&');
                log('CB-4b', authorized ? 'Consent approved -- OAuth code didapat via meta refresh' : 'Meta refresh didapat', 'success');
                log('CB-4b', `Callback: ${COLOR.gray}${ghRedirect.slice(0, 100)}...${COLOR.reset}`, 'info');
            } else {
                log('CB-4b', 'Consent diproses tapi callback URL tidak ditemukan', 'error');
                fs.writeFileSync('cb_consent_debug.html', cBody);
                return { ok: false, reason: 'consent no callback' };
            }
        }
    }

    if (!ghRedirect) {
        log('CB-4', 'Authorize tidak menghasilkan redirect', 'error');
        return { ok: false, reason: 'authorize no redirect' };
    }

    
    
    
    if (ghRedirect.includes('github.com/dashboard') || ghRedirect === 'https://github.com/') {
        const dashRes = await axios.get('https://github.com/dashboard', buildAxiosConfig({
            Host: 'github.com',
            Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Dest': 'document',
            Referer: ghAuthUrl,
        }, buildCookieString(ghCookies)));
        const dashBody = typeof dashRes.data === 'string' ? dashRes.data : '';
        if (/This account is flagged/i.test(dashBody)) {
            log('CB-4', 'AKUN FLAGGED -- tidak bisa authorize OAuth ke pihak ketiga', 'fatal');
            log('CB-4', '   GitHub: "This account is flagged, and therefore cannot authorize a third party application."', 'error');
            log('CB-4', '   Solusi: pakai akun lain atau ajukan review ke GitHub Support.', 'warn');
            return { ok: false, reason: 'account-flagged', flagged: true };
        }
        log('CB-4', 'Redirect ke dashboard tanpa flash flagged -- kemungkinan state OAuth invalid', 'warn');
        return { ok: false, reason: 'redirected-to-dashboard' };
    }

    
    
    delete cbCookies.KC_STATE_CHECKER;

    
    
    const sessionBackup = cbCookies.session || null;

    
    
    
    
    
    
    
    const callbackUrl = ghRedirect.startsWith('http') ? ghRedirect : `https://github.com${ghRedirect}`;
    log('CB-5', `GET broker callback: ${callbackUrl.slice(0, 120)}`, 'request');

    const cbRes = await axios.get(callbackUrl, buildAxiosConfig({
        Host: 'www.codebuddy.ai',
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Sec-Fetch-Site': 'cross-site',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Dest': 'document',
        Referer: 'https://github.com/',
        'Accept-Encoding': 'gzip, deflate, br',
        Priority: 'u=0, i',
    }, buildCookieString(cbCookies), true));
    log('CB-5', `Callback status: ${cbRes.status}`, (cbRes.status === 302 || cbRes.status === 303) ? 'success' : 'warn');
    const callbackLocation = cbRes.headers['location'] || '';
    if (callbackLocation) log('CB-5', `Location: ${callbackLocation.slice(0, 120)}`, 'info');
    logCookies('CB-5', cbRes.headers['set-cookie'], 'Set-Cookie');
    mergeCookiesKeep(cbCookies, cbRes.headers['set-cookie']);

    
    
    
    
    
    let loginSelectCodeUrl = ''; 
    if ((cbRes.status === 302 || cbRes.status === 303) && callbackLocation) {
        let chainUrl = callbackLocation;
        for (let hop = 1; hop <= 6 && chainUrl; hop++) {
            const hopUrl = chainUrl.startsWith('http') ? chainUrl : `https://www.codebuddy.ai${chainUrl}`;
            log('CB-5f', `HOP ${hop}: GET ${hopUrl.slice(0, 110)}`, 'request');
            const hopRes = await axios.get(hopUrl, buildAxiosConfig({
                Host: 'www.codebuddy.ai',
                Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'Sec-Fetch-Site': 'cross-site',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-User': '?1',
                'Sec-Fetch-Dest': 'document',
                'Accept-Encoding': 'gzip, deflate, br',
                Priority: 'u=0, i',
            }, buildCookieString(cbCookies), true));
            log('CB-5f', `HOP ${hop} status: ${hopRes.status}`, (hopRes.status === 302 || hopRes.status === 303) ? 'success' : 'warn');
            logCookies('CB-5f', hopRes.headers['set-cookie'], `HOP ${hop} Set-Cookie`);
            mergeCookiesKeep(cbCookies, hopRes.headers['set-cookie']);

            const nextLoc = hopRes.headers['location'] || '';
            if (nextLoc) log('CB-5f', `HOP ${hop} Location: ${nextLoc.slice(0, 120)}`, 'info');
            if (cbCookies.KEYCLOAK_SESSION && cbCookies.KEYCLOAK_IDENTITY) {
                log('CB-5f', 'KEYCLOAK_SESSION + KEYCLOAK_IDENTITY didapat -- broker chain selesai', 'success');
                loginSelectCodeUrl = nextLoc;
                break;
            }
            if (!nextLoc || (hopRes.status !== 302 && hopRes.status !== 303)) {
                loginSelectCodeUrl = nextLoc || '';
                
                log('CB-5f', `  server: ${hopRes.headers['server'] || '-'}, waf: ${hopRes.headers['x-waf-uuid'] || '-'}, type: ${hopRes.headers['content-type'] || '-'}`, 'warn');
                const hopBody = typeof hopRes.data === 'string' ? hopRes.data : '';
                if (hopBody) log('CB-5f', `  body: ${hopBody.slice(0, 300).replace(/\s+/g, ' ')}`, 'warn');
                
                
                if (/Access Restricted/i.test(hopBody)) {
                    log('CB-5f', 'AKUN CODEBUDDY DI-RESTRICT SEMENTARA oleh security policy Tencent', 'fatal');
                    log('CB-5f', '   ("Account Access Restricted -- temporarily unavailable due to security policy restrictions")', 'error');
                    log('CB-5f', '   Penyebab umum: terlalu banyak percobaan login otomatis dalam waktu singkat.', 'error');
                    log('CB-5f', '   Solusi: tunggu 30-60 menit lalu coba lagi; kalau masih blokir, hubungi Tencent Cloud Support.', 'warn');
                    return { ok: false, reason: 'account-access-restricted', cbCookies };
                }
                break;
            }
            chainUrl = nextLoc;
            loginSelectCodeUrl = nextLoc;
        }
    }

    
    
    if (cbRes.status === 400) {
        log('CB-5', 'Callback broker 400, lanjutkan resume session', 'warn');
    }

    
    if (!cbCookies.session && sessionBackup) {
        cbCookies.session = sessionBackup;
        log('CB-5', 'Session di-restore dari backup', 'cookie');
    }

    
    
    log('CB-5b', 'POST /console/auth/risk-context', 'request');
    try {
        const riskRes = await axios.post('https://www.codebuddy.ai/console/auth/risk-context', '', buildAxiosConfig({
            Host: 'www.codebuddy.ai',
            'Sec-Ch-Ua-Platform': '"macOS"',
            'Accept-Language': 'id-ID,id;q=0.9',
            'Sec-Ch-Ua': '"Chromium";v="151", "Not=A?Brand";v="99"',
            'Sec-Ch-Ua-Mobile': '?0',
            'X-Device-Token': CONFIG.cbDeviceToken,
            'X-Domain': 'www.codebuddy.ai',
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': CONFIG.userAgent,
            Accept: 'application/json, text/plain, */*',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Dest': 'empty',
            Referer: 'https://www.codebuddy.ai/',
            'Accept-Encoding': 'gzip, deflate, br',
            Priority: 'u=1, i',
        }, buildCookieString(cbCookies), true));
        mergeCookiesKeep(cbCookies, riskRes.headers['set-cookie']);
        log('CB-5b', `Status: ${riskRes.status}`, riskRes.status === 200 ? 'success' : 'warn');
    } catch (e) {
        log('CB-5b', `Risk-context skip: ${e.message}`, 'warn');
    }

    
    
    
    
    
    async function resumeConsoleAccounts(refererOverride = null) {
        const referer = refererOverride || loginSelectCodeUrl || cbLoginSelect;
        log('CB-5c', 'GET /console/accounts (resume session)', 'request');
        const accRes1 = await axios.get(cbAccountsUrl, buildAxiosConfig(
            buildCbApiHeaders(referer),
            buildCookieString(cbCookies),
            true
        ));
        log('CB-5c', `Status: ${accRes1.status}`, accRes1.status === 302 ? 'success' : 'warn');
        logCookies('CB-5c', accRes1.headers['set-cookie'], 'Set-Cookie');
        mergeCookiesKeep(cbCookies, accRes1.headers['set-cookie']);

        let kcTarget = accRes1.headers['location'] || '';
        if (accRes1.status === 302 && kcTarget) {
            if (kcTarget.startsWith('/')) kcTarget = `https://www.codebuddy.ai${kcTarget}`;
            log('CB-5c', `Location: ${kcTarget.slice(0, 130)}`, 'info');

            
            log('CB-5c1', `GET keycloak auth`, 'request');
            const kcRes = await axios.get(kcTarget, buildAxiosConfig(
                buildCbApiHeaders(referer),
                buildCookieString(cbCookies),
                true
            ));
            log('CB-5c1', `Status: ${kcRes.status}`, kcRes.status === 302 ? 'success' : 'warn');
            logCookies('CB-5c1', kcRes.headers['set-cookie'], 'Set-Cookie');
            mergeCookiesKeep(cbCookies, kcRes.headers['set-cookie']);

            let apisixLoc = kcRes.headers['location'] || '';
            if (apisixLoc) log('CB-5c1', `Location: ${apisixLoc.slice(0, 130)}`, 'info');
            if (kcRes.status === 302 && apisixLoc) {
                if (apisixLoc.startsWith('/')) apisixLoc = `https://www.codebuddy.ai${apisixLoc}`;
                log('CB-5c2', `GET apisix redirect`, 'request');
                const apisixRes = await axios.get(apisixLoc, buildAxiosConfig(
                    buildCbApiHeaders(referer),
                    buildCookieString(cbCookies),
                    true
                ));
                log('CB-5c2', `Status: ${apisixRes.status}`, apisixRes.status === 302 ? 'success' : 'warn');
                logCookies('CB-5c2', apisixRes.headers['set-cookie'], 'Set-Cookie');
                mergeCookiesKeep(cbCookies, apisixRes.headers['set-cookie']);

                let finalLoc = apisixRes.headers['location'] || '';
                if (finalLoc) log('CB-5c2', `Location: ${finalLoc.slice(0, 130)}`, 'info');
                if (apisixRes.status === 302 && finalLoc) {
                    if (finalLoc.startsWith('/')) finalLoc = `https://www.codebuddy.ai${finalLoc}`;
                    log('CB-5c3', `GET ${finalLoc.slice(0, 90)}`, 'request');
                    const finalAccRes = await axios.get(finalLoc, buildAxiosConfig(
                        buildCbApiHeaders(referer),
                        buildCookieString(cbCookies),
                        true
                    ));
                    log('CB-5c3', `Status: ${finalAccRes.status}`, finalAccRes.status === 200 ? 'success' : 'warn');
                    logCookies('CB-5c3', finalAccRes.headers['set-cookie'], 'Set-Cookie');
                    mergeCookiesKeep(cbCookies, finalAccRes.headers['set-cookie']);
                    return finalAccRes;
                }
            }
        }
        return accRes1;
    }
    await resumeConsoleAccounts();

    
    
    if (!cbCookies.KEYCLOAK_SESSION && !cbCookies.KEYCLOAK_IDENTITY && cbTabId) {
        log('CB-5d', 'Fallback: GET /login/select untuk aktifkan keycloak context', 'warn');
        try {
            const selectRes = await axios.get(cbLoginSelect, buildAxiosConfig({
                Host: 'www.codebuddy.ai',
                Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Dest': 'document',
                Referer: ghAuthUrl,
            }, buildCookieString(cbCookies), true));
            mergeCookiesKeep(cbCookies, selectRes.headers['set-cookie']);
            log('CB-5d', `Status: ${selectRes.status}`, selectRes.status === 200 ? 'success' : 'warn');
        } catch (e) {
            log('CB-5d', `Fallback error: ${e.message}`, 'warn');
        }
    }

    
    
    if (!cbCookies.session_2) {
        log('CB-5e', 'Fallback: GET /console/accounts dengan Referer /login/select', 'warn');
        try {
            const accRes = await axios.get(cbAccountsUrl, buildAxiosConfig(
                buildCbApiHeaders(cbLoginSelect),
                buildCookieString(cbCookies),
                true
            ));
            mergeCookiesKeep(cbCookies, accRes.headers['set-cookie']);
            log('CB-5e', `Status: ${accRes.status}`, accRes.status === 302 ? 'success' : 'warn');
            if (accRes.status === 302 && accRes.headers['location']) {
                log('CB-5e', `Location: ${accRes.headers['location'].slice(0, 130)}`, 'info');
                await resumeConsoleAccounts(cbLoginSelect);
            }
        } catch (e) {
            log('CB-5e', `Fallback error: ${e.message}`, 'warn');
        }
    }

    
    
    let finalCheck;
    for (let attempt = 1; attempt <= 3; attempt++) {
        log('CB-6', `GET /console/accounts (final validation attempt ${attempt})`, 'request');
        finalCheck = await axios.get('https://www.codebuddy.ai/console/accounts', buildAxiosConfig(
            buildCbApiHeaders(cbConsoleReferer),
            buildCookieString(cbCookies),
            true
        ));
        log('CB-6', `Status: ${finalCheck.status}`, finalCheck.status === 200 ? 'success' : 'warn');
        if (finalCheck.status === 200) break;
        if (finalCheck.status === 302 && finalCheck.headers['location']) {
            log('CB-6', `Location: ${finalCheck.headers['location'].slice(0, 130)}`, 'info');
        }
        if (finalCheck.status === 302 && attempt < 3) {
            log('CB-6', 'Masih 302, retry resume session...', 'warn');
            mergeCookiesKeep(cbCookies, finalCheck.headers['set-cookie']);
            await sleep(500 + Math.floor(Math.random() * 500));
            await resumeConsoleAccounts();
            await sleep(500 + Math.floor(Math.random() * 500));
        }
    }
    if (finalCheck.status === 200) {
        try {
            const j = typeof finalCheck.data === 'string' ? JSON.parse(finalCheck.data) : finalCheck.data;
            const accounts = j.data && j.data.accounts ? j.data.accounts : [];
            if (accounts.length) {
                log('CB-6', `Akun aktif: ${COLOR.gray}${accounts[0].nickname}${COLOR.reset}`, 'success');
            } else {
                log('CB-6', 'Tidak ada akun di response /console/accounts', 'warn');
            }
        } catch (e) {
            log('CB-6', 'Response /console/accounts bukan JSON', 'warn');
        }
    }

    
    const loginOk = finalCheck && finalCheck.status === 200;
    const finalUrl = finalCheck && finalCheck.request && finalCheck.request.res && finalCheck.request.res.responseUrl
        ? finalCheck.request.res.responseUrl
        : 'https://www.codebuddy.ai/console/accounts';
    const result = {
        email,
        codebuddyCookies: cbCookies,
        githubCookies: ghCookies,
        codebuddyCookieString: buildCookieString(cbCookies),
        finalUrl,
        createdAt: new Date().toISOString(),
    };
    fs.mkdirSync(outDir, { recursive: true });
    fs.writeFileSync(path.join(outDir, 'codebuddy_session.json'), JSON.stringify(result, null, 2));
    log('CB-7', `Session codebuddy disimpan ke ${path.join(outDir, 'codebuddy_session.json')}`, 'cookie');

    
    if (!loginOk) {
        log('CB-7', `PERINGATAN: /console/accounts status ${finalCheck ? finalCheck.status : 'unknown'} -- login belum sempurna`, 'warn');
        log('CB-7', `  cookie tersedia: ${Object.keys(cbCookies).join(', ')}`, 'warn');
        return { ok: false, reason: `console-accounts-status-${finalCheck ? finalCheck.status : 'unknown'}`, cbCookies };
    }
    log('CB-7', `Session codebuddy valid ("session" ${cbCookies.session.length} char)`, 'success');

    console.log();
    
    
    

    return { ok: true, finalUrl, cbCookies };
}

const ROUTER9 = {
    baseUrl: process.env.ROUTER9_URL || 'http://localhost:20128',
    password: process.env.ROUTER9_PASS || '123456',
    provider: 'codebuddy-intl',
};

async function router9Login() {
    log('R9-Login', `POST ${ROUTER9.baseUrl}/api/auth/login`, 'request');
    const res = await axios.post(
        `${ROUTER9.baseUrl}/api/auth/login`,
        { password: ROUTER9.password },
        {
            headers: {
                Host: new URL(ROUTER9.baseUrl).host,
                'Content-Type': 'application/json',
                'User-Agent': CONFIG.userAgent,
                Accept: '*/*',
                Origin: ROUTER9.baseUrl,
                Referer: `${ROUTER9.baseUrl}/login`,
            },
            timeout: 15000,
            maxRedirects: 0,
            validateStatus: () => true,
        }
    );
    if (res.status !== 200) {
        log('R9-Login', `Login 9router gagal: status ${res.status}`, 'error');
        return null;
    }
    
    const setCookies = extractCookies(res.headers['set-cookie']);
    let authToken = setCookies.auth_token || null;
    if (!authToken && res.data && res.data.data && res.data.data.auth_token) {
        authToken = res.data.data.auth_token;
    }
    if (!authToken) {
        log('R9-Login', 'auth_token tidak ditemukan di response', 'error');
        return null;
    }
    log('R9-Login', 'Login 9router OK -- auth_token didapat', 'success');
    return authToken;
}

async function router9DeviceCode(authToken) {
    log('R9-DC', `GET /api/oauth/${ROUTER9.provider}/device-code`, 'request');
    const res = await axios.get(
        `${ROUTER9.baseUrl}/api/oauth/${ROUTER9.provider}/device-code`,
        {
            headers: {
                Host: new URL(ROUTER9.baseUrl).host,
                'User-Agent': CONFIG.userAgent,
                Accept: '*/*',
                Cookie: `auth_token=${authToken}`,
                Referer: `${ROUTER9.baseUrl}/dashboard/providers/${ROUTER9.provider}`,
            },
            timeout: 15000,
            maxRedirects: 0,
            validateStatus: () => true,
        }
    );
    if (res.status !== 200 || !res.data || !res.data.device_code) {
        log('R9-DC', `Gagal ambil device code: status ${res.status}`, 'error');
        if (res.data) log('R9-DC', JSON.stringify(res.data).slice(0, 200), 'warn');
        return null;
    }
    const { device_code, verification_uri, interval, codeVerifier } = res.data;
    log('R9-DC', `device_code: ${COLOR.gray}${device_code}${COLOR.reset}`, 'success');
    log('R9-DC', `verification_uri: ${COLOR.gray}${verification_uri}${COLOR.reset}`, 'info');
    return { deviceCode: device_code, verificationUri: verification_uri, interval: interval || 5, codeVerifier };
}

async function approveCodebuddyDevice(cbCookies, deviceCode) {
    const DOMAIN = 'www.codebuddy.ai';
    const loginReferer = `https://${DOMAIN}/login?platform=ide&state=${deviceCode}`;
    const homeReferer = 'https://www.codebuddy.ai/home';

    
    
    let accRes = null;
    let nick = null;
    for (let attempt = 1; attempt <= 3; attempt++) {
        log('CB-Dev', `Validasi session codebuddy (GET /console/accounts, attempt ${attempt})`, 'request');
        accRes = await axios.get(`https://${DOMAIN}/console/accounts`, buildAxiosConfig(
            buildCbApiHeaders(homeReferer),
            buildCookieString(cbCookies),
            true
        ));
        log('CB-Dev', `Status: ${accRes.status}`, accRes.status === 200 ? 'success' : 'warn');
        if (accRes.status === 200) {
            try {
                const j = typeof accRes.data === 'string' ? JSON.parse(accRes.data) : accRes.data;
                const accounts = j.data && j.data.accounts ? j.data.accounts : [];
                nick = accounts.length ? `${accounts[0].nickname} (uin ${accounts[0].uin})` : null;
            } catch (e) {  }
            if (nick) break;
        }
        if (attempt < 3) {
            log('CB-Dev', 'Session belum siap, tunggu sebentar...', 'wait');
            await sleep(1000 + Math.floor(Math.random() * 1000));
        }
    }
    if (!accRes || accRes.status !== 200) {
        log('CB-Dev', `Session codebuddy invalid: status ${accRes ? accRes.status : 'no response'}`, 'error');
        return false;
    }
    if (!nick) {
        log('CB-Dev', 'Session codebuddy tidak punya akun login', 'error');
        return false;
    }
    log('CB-Dev', `Session valid: ${COLOR.gray}${nick}${COLOR.reset}`, 'success');

    await sleep(800 + Math.floor(Math.random() * 800));

    
    log('CB-Dev', `GET /console/auth/login?platform=ide&state=${deviceCode.slice(0, 8)}...`, 'request');
    const res = await axios.get(`https://${DOMAIN}/console/auth/login?platform=ide&state=${deviceCode}&domain=${DOMAIN}`, buildAxiosConfig(
        buildCbApiHeaders(loginReferer),
        buildCookieString(cbCookies),
        true
    ));
    log('CB-Dev', `Status: ${res.status}`, res.status === 302 ? 'success' : 'warn');
    mergeCookies(cbCookies, res.headers['set-cookie']);
    logCookies('CB-Dev', res.headers['set-cookie'], 'Set-Cookie');
    if (res.status !== 302) {
        const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
        log('CB-Dev', `Body: ${body.slice(0, 300)}`, 'warn');
        return false;
    }
    log('CB-Dev', `Location: ${COLOR.gray}${res.headers['location'] || 'none'}${COLOR.reset}`, 'info');
    
    log('CB-Dev', 'Device code terkirim ke codebuddy', 'success');
    return true;
}

async function router9Poll(authToken, deviceCode, codeVerifier, intervalSec) {
    const interval = (intervalSec || 5) * 1000;
    const maxAttempts = 24; 
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        await sleep(interval);
        log('R9-Poll', `Attempt ${attempt}/${maxAttempts}`, 'request');
        const res = await axios.post(
            `${ROUTER9.baseUrl}/api/oauth/${ROUTER9.provider}/poll`,
            { deviceCode, codeVerifier, extraData: null },
            {
                headers: {
                    Host: new URL(ROUTER9.baseUrl).host,
                    'Content-Type': 'application/json',
                    'User-Agent': CONFIG.userAgent,
                    Accept: '*/*',
                    Origin: ROUTER9.baseUrl,
                    Cookie: `auth_token=${authToken}`,
                    Referer: `${ROUTER9.baseUrl}/dashboard/providers/${ROUTER9.provider}`,
                },
                timeout: 15000,
                maxRedirects: 0,
                validateStatus: () => true,
            }
        );
        const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
        if (res.status === 200 && res.data && res.data.success) {
            log('R9-Poll', `Koneksi terbentuk: ${COLOR.gray}id=${res.data.connection.id}${COLOR.reset}`, 'success');
            return res.data.connection;
        }
        
        log('R9-Poll', `Status ${res.status}: ${body.slice(0, 120)}`, 'wait');
    }
    log('R9-Poll', 'Timeout menunggu approval device code', 'error');
    return null;
}

async function linkCodebuddyTo9router(cbCookies, outDir = process.cwd()) {
    const authToken = await router9Login();
    if (!authToken) return { ok: false, reason: 'router9-login-failed' };

    const dc = await router9DeviceCode(authToken);
    if (!dc) return { ok: false, reason: 'device-code-failed' };

    await sleep(1000);
    const approved = await approveCodebuddyDevice(cbCookies, dc.deviceCode);
    if (!approved) return { ok: false, reason: 'device-approve-failed' };

    const connection = await router9Poll(authToken, dc.deviceCode, dc.codeVerifier, dc.interval);
    if (!connection) return { ok: false, reason: 'poll-timeout' };

    
    const out = {
        provider: ROUTER9.provider,
        connectionId: connection.id,
        linkedAt: new Date().toISOString(),
    };
    fs.mkdirSync(outDir, { recursive: true });
    fs.writeFileSync(path.join(outDir, 'codebuddy_9router_link.json'), JSON.stringify(out, null, 2));
    log('R9-Link', `Hasil link disimpan ke ${path.join(outDir, 'codebuddy_9router_link.json')}`, 'cookie');

    log('R9-Link', `Codebuddy <-> 9router linked: ${ROUTER9.provider} / ${connection.id}`, 'success');

    return { ok: true, connection };
}

async function main() {
    
    
    const accounts = [];
    const seen = new Set();
    const pushAcc = (email, password, twoFa) => {
        if (!email || seen.has(email.toLowerCase())) return;
        seen.add(email.toLowerCase());
        accounts.push({ email, password, twoFa });
    };
    try {
        if (fs.existsSync('codebuddy.txt')) {
            for (const line of fs.readFileSync('codebuddy.txt', 'utf8').split(/\r?\n/)) {
                const parts = line.trim().split('|');
                if (parts.length >= 3 && parts[0].includes('@')) {
                    pushAcc(parts[0], parts[1], parts[3] || '');
                }
            }
        }
    } catch (e) {  }

    if (!accounts.length) {
        log('Main', 'Tidak ada akun untuk diproses (codebuddy.txt kosong/tidak ada)', 'error');
        process.exit(1);
    }
    log('Main', `Total akun dari codebuddy.txt: ${accounts.length}`, 'info');
    log('Main', `Concurrency: ${CONFIG.concurrency} akun bersamaan (atur via env CONCURRENCY, maks 10)`, 'info');
    log('Main', `Delay antar akun: ${CONFIG.delayMs}ms (atur via env DELAY_MS)`, 'info');

    
    const failures = [];
    const successes = [];
    const processing = new Set();

    async function processAccount(acc, index) {
        const slot = processing.size + 1;
        processing.add(acc.email);
        const prefix = `[${slot}/${CONFIG.concurrency}]`;
        log('Main', `${prefix} ========== AKUN ${index + 1}/${accounts.length}: ${acc.email} ==========`, 'request');

        
        const safeEmail = acc.email.replace(/[^a-z0-9_.-]/gi, '_');
        const outDir = path.join('results', safeEmail);

        
        
        CONFIG.userAgent = process.env.USER_AGENT || pickUserAgent();
        CONFIG.proxy = process.env.PROXY || buildStickyProxy();
        CONFIG.cbDeviceToken = process.env.CB_DEVICE_TOKEN || pickDeviceToken();
        log('Config', `${prefix} UA: ${COLOR.gray}${CONFIG.userAgent.split(')')[0]})...${COLOR.reset}`, 'info');
        log('Config', `${prefix} Using proxy: ${COLOR.gray}${CONFIG.proxy}${COLOR.reset}`, 'info');

        let needsCooldown = false;
        let cooldownReason = '';

        try {
            const { isLoggedIn, cookies } = await loginGitHub(acc.email, acc.password, acc.twoFa, outDir);
            if (!isLoggedIn) {
                log('Main', `${prefix} GitHub login gagal untuk ${acc.email}`, 'warn');
                failures.push({ email: acc.email, stage: 'github' });
                return;
            }

            log('Codebuddy', `${prefix} Memulai login codebuddy.ai via GitHub OAuth...`, 'request');
            const cbResult = await loginCodebuddy(cookies, acc.email, outDir);
            if (!cbResult.ok) {
                log('Codebuddy', `${prefix} Login codebuddy gagal: ${cbResult.reason}`, 'error');
                failures.push({ email: acc.email, stage: 'codebuddy', reason: cbResult.reason });
                
                if (/flagged|access-restricted|security policy|temporarily unavailable|rate|429/i.test(cbResult.reason || '')) {
                    needsCooldown = true;
                    cooldownReason = `codebuddy ${cbResult.reason}`;
                }
                return;
            }
            log('Codebuddy', `${prefix} Login codebuddy berhasil`, 'success');

            log('9router', `${prefix} Menghubungkan codebuddy ke 9router via device code...`, 'request');
            const linkResult = await linkCodebuddyTo9router(cbResult.cbCookies, outDir);
            if (!linkResult.ok) {
                log('9router', `${prefix} Link 9router gagal: ${linkResult.reason}`, 'error');
                failures.push({ email: acc.email, stage: '9router', reason: linkResult.reason });
                return;
            }

            log('Main', `${prefix} SUKSES dengan akun ${acc.email}`, 'success');
            successes.push(acc.email);
        } catch (err) {
            log('Main', `${prefix} Error tak terduga untuk ${acc.email}: ${err.message}`, 'error');
            failures.push({ email: acc.email, stage: 'error', reason: err.message });
        } finally {
            processing.delete(acc.email);
            
            
            if (needsCooldown) {
                const delay = 15000 + Math.floor(Math.random() * 15000);
                log('Config', `${prefix} Cooldown ${delay / 1000}d karena ${cooldownReason}`, 'wait');
                await sleep(delay);
            }
        }
    }

    async function asyncPool(poolLimit, array, iteratorFn) {
        const ret = [];
        const executing = [];
        for (const [index, item] of array.entries()) {
            
            if (index > 0 && CONFIG.delayMs > 0) {
                const jitter = Math.floor(Math.random() * CONFIG.delayMs);
                log('Main', `Menunggu ${((CONFIG.delayMs + jitter) / 1000).toFixed(1)}d sebelum akun berikutnya...`, 'wait');
                await sleep(CONFIG.delayMs + jitter);
            }
            const p = Promise.resolve().then(() => iteratorFn(item, index));
            ret.push(p);
            if (poolLimit <= array.length) {
                const e = p.then(() => undefined);
                executing.push(e);
                if (executing.length >= poolLimit) {
                    await Promise.race(executing);
                    executing.splice(executing.findIndex((x) => x === e), 1);
                }
            }
        }
        return Promise.all(ret);
    }

    await asyncPool(CONFIG.concurrency, accounts, processAccount);

    
    const BAD_ACCOUNTS_FILE = path.join(__dirname, 'bad_accounts.txt');
    const knownBad = fs.existsSync(BAD_ACCOUNTS_FILE)
        ? new Set(fs.readFileSync(BAD_ACCOUNTS_FILE, 'utf8').split(/\r?\n/).map((s) => s.trim().toLowerCase()).filter(Boolean))
        : new Set();

    log('Main', `========== RINGKASAN ==========`, 'info');
    log('Main', `Sukses: ${successes.length}/${accounts.length}`, successes.length ? 'success' : 'warn');
    for (const email of successes) log('Main', `  [OK] ${email}`, 'success');
    log('Main', `Gagal: ${failures.length}/${accounts.length}`, failures.length ? 'warn' : 'success');
    for (const f of failures) {
        log('Main', `  [X]  ${f.email}: ${f.stage}${f.reason ? ` (${f.reason})` : ''}`, 'warn');
        const reason = f.reason || f.stage || '';
        if (/flagged|suspended|access-restricted|security policy|temporarily unavailable/i.test(reason)) {
            const key = `${f.email.toLowerCase()}|${reason}`;
            if (!knownBad.has(key)) {
                knownBad.add(key);
                fs.appendFileSync(BAD_ACCOUNTS_FILE, `${key}\n`);
            }
        }
    }
    process.exit(successes.length ? 0 : 1);
}

main().catch((err) => {
    log('Fatal', err.message, 'fatal');
    process.exit(1);
});
