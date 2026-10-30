/**
 * 大连交通大学 空教室查询 - 本地代理服务
 *
 * 工作原理:
 *  1. 前端请求 /api/captcha,后端向教务处申请会话(JSESSIONID)并取回验证码图片
 *  2. 前端提交账号/密码/验证码,后端按教务处登录页的原始逻辑
 *     (密码双重 MD5,GET j_acegi_security_check)完成登录,会话 Cookie 保存在内存
 *  3. 登录后调用 /academic/teacher/teachresource/roomschedule_week.jsdo
 *     解析整栋楼的教室占用表,换算出空教室
 *
 * 零 npm 依赖,Node >= 18 直接运行: node server.js
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

const PORT = process.env.PORT || 8321;
const HOST = process.env.HOST || '0.0.0.0'; // 手机访问需要监听局域网,如需仅本机可设 HOST=127.0.0.1
const JW_BASE = 'http://jw.djtu.edu.cn';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36';

// 允许跨域调用本服务的前端来源(本机 + GitHub Pages)
const ALLOWED_ORIGIN_RE = /^https?:\/\/(localhost(:\d+)?|127\.0\.0\.1(:\d+)?|[\w-]+\.github\.io)$/;

function corsHeaders(req) {
  const origin = req.headers.origin || '';
  if (origin && ALLOWED_ORIGIN_RE.test(origin)) {
    return {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Max-Age': '86400',
      Vary: 'Origin',
    };
  }
  return {};
}

/* ---------------- 校区 / 教学楼(来自教务处"教室查询"模块,可用参数校准) ---------------- */
const CAMPUSES = [
  {
    id: 1, name: '沙河口校区',
    buildings: [
      { id: 80, name: '1号楼', def: true },
      { id: 97, name: '2号楼', def: true },
      { id: 160, name: '3号楼', def: true },
      { id: 187, name: '4号楼', def: true },
      { id: 224, name: '5实验馆', def: false },
      { id: 213, name: '6图书馆', def: false },
      { id: 282, name: '7南区教学楼', def: true },
      { id: 3302, name: '8南区实验楼', def: false },
      { id: 3201, name: '马克思学院楼', def: true },
    ],
  },
  {
    id: 78, name: '旅顺口校区',
    buildings: [
      { id: 521, name: 'R2号楼', def: true },
      { id: 522, name: 'R3号楼', def: true },
      { id: 2561, name: 'R4号楼', def: true },
      { id: 523, name: 'R5号楼', def: true },
      { id: 524, name: 'R6号楼', def: true },
      { id: 525, name: 'R7号楼', def: true },
      { id: 526, name: 'R8号楼', def: true },
      { id: 527, name: 'R9号楼', def: true },
      { id: 3362, name: 'R13号楼', def: true },
      { id: 1061, name: '教学楼', def: false },
      { id: 1741, name: '创新楼', def: false },
      { id: 1781, name: '研究生楼', def: false },
      { id: 1062, name: '图书馆', def: false },
    ],
  },
];

const DAY_NAMES = { 1: '周一', 2: '周二', 3: '周三', 4: '周四', 5: '周五', 6: '周六', 7: '周日' };

/* ---------------- 会话存储(仅内存,进程退出即清空) ---------------- */
const sessions = new Map(); // sid -> { jar: Map, username, createdAt }
const SESSION_TTL = 30 * 60 * 1000;

function newSid() {
  return crypto.randomBytes(16).toString('hex');
}

function getSession(sid) {
  const s = sessions.get(sid);
  if (!s) return null;
  if (Date.now() - s.createdAt > SESSION_TTL) {
    sessions.delete(sid);
    return null;
  }
  return s;
}

/* ---------------- 带会话 Cookie 的请求封装 ---------------- */
function cookieHeader(jar) {
  return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
}

async function jarFetch(jar, url, { method = 'GET', body, maxRedirects = 6, timeoutMs = 25000, referer } = {}) {
  let current = url;
  let resp = null;
  for (let i = 0; i <= maxRedirects; i++) {
    const headers = { 'User-Agent': UA, Referer: referer || JW_BASE + '/academic/common/security/affairLogin.jsp' };
    if (jar.size) headers.Cookie = cookieHeader(jar);
    if (body !== undefined) headers['Content-Type'] = 'application/x-www-form-urlencoded';
    resp = await fetch(current, {
      method, headers,
      body: body !== undefined ? body : undefined,
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs),
    });
    const setCookies = typeof resp.headers.getSetCookie === 'function' ? resp.headers.getSetCookie() : [];
    for (const c of setCookies) {
      const kv = c.split(';')[0];
      const eq = kv.indexOf('=');
      if (eq > 0) jar.set(kv.slice(0, eq).trim(), kv.slice(eq + 1).trim());
    }
    if (resp.status >= 300 && resp.status < 400) {
      const loc = resp.headers.get('location');
      if (loc) {
        current = new URL(loc, current).href;
        if (method !== 'GET') { method = 'GET'; body = undefined; }
        continue;
      }
    }
    break;
  }
  return resp;
}

async function readGBK(resp) {
  const buf = Buffer.from(await resp.arrayBuffer());
  return new TextDecoder('gbk').decode(buf);
}

// showHeader.do 返回 UTF-8,其余页面为 GBK;先 UTF-8 解码,无目标字样再回退 GBK
async function readAuto(resp, probe = '您好') {
  const buf = Buffer.from(await resp.arrayBuffer());
  const utf8 = buf.toString('utf8');
  if (utf8.includes(probe)) return utf8;
  return new TextDecoder('gbk').decode(buf);
}

/* ---------------- 教务处接口 ---------------- */
async function fetchCaptcha(jar) {
  // 1. 访问登录页拿到 JSESSIONID
  const loginPage = await jarFetch(jar, `${JW_BASE}/academic/common/security/affairLogin.jsp`);
  await loginPage.arrayBuffer();
  // 2. 取验证码图片
  const cap = await jarFetch(jar, `${JW_BASE}/academic/getCaptcha.do?captchaCheckCode=0&random=${Date.now()}`);
  const buf = Buffer.from(await cap.arrayBuffer());
  if (!buf.length) throw new Error('验证码获取失败');
  const isJpeg = buf[0] === 0xff && buf[1] === 0xd8;
  const mime = isJpeg ? 'image/jpeg' : 'image/png';
  return `data:${mime};base64,${buf.toString('base64')}`;
}

function doubleMd5(password) {
  const once = crypto.createHash('md5').update(password, 'utf8').digest('hex');
  return crypto.createHash('md5').update(once, 'utf8').digest('hex');
}

async function doLogin(jar, username, password, captcha) {
  const enc = (s) => encodeURIComponent(s);
  const url = `${JW_BASE}/academic/j_acegi_security_check?j_username=${enc(username)}&j_password=${enc(doubleMd5(password))}&j_captcha=${enc(captcha)}`;
  const resp = await jarFetch(jar, url);
  const finalBody = resp ? await readGBK(resp) : '';
  const finalUrl = resp ? resp.url : '';

  // 登录成功后用 listLeft.do 验证会话并解析当前学期周次
  const menuResp = await jarFetch(jar, `${JW_BASE}/academic/listLeft.do?randomString=${Date.now()}`);
  const menuHtml = await readGBK(menuResp);
  if (!menuHtml.includes('menuWrap') || menuHtml.includes('affairLogin.jsp')) {
    // 未登录成功:根据跳转判断失败原因
    if (/验证码/i.test(finalBody) || /login_error/.test(finalUrl)) return { ok: false, error: '验证码不正确' };
    if (finalUrl.includes('affairLogin.jsp')) return { ok: false, error: '用户名、密码或验证码错误' };
    return { ok: false, error: '登录失败,请检查账号密码后重试' };
  }
  return { ok: true, ...parseSemester(menuHtml) };
}

function parseSemester(menuHtml) {
  const out = { semester: '', week: null, weekday: null, dateText: '' };
  const dateM = menuHtml.match(/(\d{4}年\d{1,2}月\d{1,2}日)[\s\S]{0,20}?(周[一二三四五六日])/);
  if (dateM) { out.dateText = dateM[1]; out.weekday = '一二三四五六日'.indexOf(dateM[2][1]) + 1; }
  const semM = menuHtml.match(/(\d{4})(秋|春|夏)[\s\S]{0,60}?第\s*(\d+)\s*周/);
  if (semM) { out.semester = semM[1] + semM[2]; out.week = parseInt(semM[3], 10); }
  return out;
}

async function fetchUserInfo(jar) {
  try {
    const resp = await jarFetch(jar, `${JW_BASE}/academic/showHeader.do?randomString=${Date.now()}`, {
      referer: JW_BASE + '/academic/index_frame.jsp',
    });
    const html = await readAuto(resp);
    const text = html.replace(/<[^>]+>/g, ' ');
    const m = text.match(/您好[\s\S]{0,30}?([\u4e00-\u9fa5·]{1,6})\s*[（(]\s*(\d{6,12})\s*[)）]/);
    if (m) return { name: m[1].trim(), username: m[2] };
    const numIdx = text.search(/\d{8}/);
    console.warn('[fetchUserInfo] 未匹配到姓名, 学号上下文:', numIdx >= 0 ? text.slice(Math.max(0, numIdx - 80), numIdx + 60) : text.replace(/\s+/g, ' ').slice(0, 200));
  } catch (e) {
    console.warn('[fetchUserInfo] 请求失败:', e.message);
  }
  return null;
}

/* ---------------- 教室占用解析 ---------------- */
function decodeEntities(s) {
  return s
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&#39;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/\s+/g, ' ')
    .trim();
}

function parseBuildingSchedule(html) {
  const titleM = html.match(/<div>([^<]*第\s*\d+\s*周[^<]*)<\/div>/);
  const title = titleM ? decodeEntities(titleM[1]) : '';
  const rooms = [];
  const rowRe = /<tr[^>]*id="tr(\d+)"[^>]*>([\s\S]*?)(?=<tr[^>]*id="tr\d+"|<\/table>\s*<\/body>|$)/g;
  let m;
  while ((m = rowRe.exec(html)) !== null) {
    const roomId = m[1];
    const seg = m[2];
    const preTable = seg.split('<table')[0];
    const info = [...preTable.matchAll(/<td[^>]*>([\s\S]*?)<\/td>/g)].map((x) => decodeEntities(x[1]));
    const nestedStart = seg.indexOf('<table');
    if (nestedStart < 0) continue;
    const nested = seg.slice(nestedStart);
    let cells = [...nested.matchAll(/<td[^>]*>([\s\S]*?)<\/td>/g)].map((x) => x[1]);
    cells = cells.filter((c) => !/第\s*\d+\s*节/.test(c) && !/座位数|排课|考试|桌椅|教室名/.test(c));
    if (!cells.length) continue;
    const occupied = [];
    cells.forEach((c, i) => { if (c.includes('●')) occupied.push(i + 1); });
    rooms.push({
      id: roomId,
      name: info[0] || '',
      seats: parseInt(info[1], 10) || 0,
      scheduleCapacity: parseInt(info[2], 10) || 0,
      examCapacity: parseInt(info[3], 10) || 0,
      furniture: info[4] || '',
      type: info[5] || '',
      totalPeriods: cells.length,
      occupied,
    });
  }
  return { title, rooms };
}

async function fetchBuildingSchedule(jar, aid, buildingId, week, day) {
  const body = `aid=${aid}&buildingid=${buildingId}&room=-1&whichweek=${week}&week=${day}`;
  const resp = await jarFetch(jar, `${JW_BASE}/academic/teacher/teachresource/roomschedule_week.jsdo`, { method: 'POST', body });
  const html = await readGBK(resp);
  if (html.includes('affairLogin.jsp') || html.includes('j_acegi_security_check') || html.includes('登录异常或登录已超时')) {
    throw new Error('SESSION_EXPIRED');
  }
  return parseBuildingSchedule(html);
}

async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let idx = 0;
  async function worker() {
    while (idx < items.length) {
      const i = idx++;
      results[i] = await fn(items[i], i);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

/* ---------------- HTTP 服务 ---------------- */
function json(res, code, data) {
  const buf = Buffer.from(JSON.stringify(data));
  const headers = { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': buf.length, ...res.__cors };
  res.writeHead(code, headers);
  res.end(buf);
}

async function readJson(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  if (!chunks.length) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch (_) { return {}; }
}

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const p = u.pathname;

  res.__cors = corsHeaders(req);

  // 跨域预检
  if (req.method === 'OPTIONS') {
    res.writeHead(204, res.__cors);
    return res.end();
  }

  try {
    /* ---- API: 验证码 ---- */
    if (p === '/api/captcha' && req.method === 'GET') {
      const sid = newSid();
      const jar = new Map();
      const img = await fetchCaptcha(jar);
      sessions.set(sid, { jar, username: null, createdAt: Date.now() });
      return json(res, 200, { ok: true, sid, img });
    }

    /* ---- API: 登录 ---- */
    if (p === '/api/login' && req.method === 'POST') {
      const { sid, username, password, captcha } = await readJson(req);
      const s = getSession(sid);
      if (!s) return json(res, 401, { ok: false, error: '会话已过期,请刷新验证码' });
      if (!username || !password || !captcha) return json(res, 400, { ok: false, error: '请填写完整的账号、密码和验证码' });
      const r = await doLogin(s.jar, String(username).trim(), String(password), String(captcha).trim());
      if (!r.ok) {
        // 失败后换新验证码(同一会话重新取图即可)
        let img = null;
        try { img = await fetchCaptcha(s.jar); } catch (_) {}
        return json(res, 200, { ok: false, error: r.error, img });
      }
      s.username = String(username).trim();
      s.createdAt = Date.now();
      const user = await fetchUserInfo(s.jar);
      return json(res, 200, { ok: true, semester: r.semester, week: r.week, weekday: r.weekday, dateText: r.dateText, user });
    }

    /* ---- API: 元信息 ---- */
    if (p === '/api/meta' && req.method === 'GET') {
      const sid = u.searchParams.get('sid');
      const s = getSession(sid);
      if (!s) return json(res, 401, { ok: false, error: '未登录或会话已过期' });
      const menuResp = await jarFetch(s.jar, `${JW_BASE}/academic/listLeft.do?randomString=${Date.now()}`);
      const menuHtml = await readGBK(menuResp);
      if (!menuHtml.includes('menuWrap')) return json(res, 401, { ok: false, error: '登录已过期,请重新登录' });
      return json(res, 200, { ok: true, ...parseSemester(menuHtml) });
    }

    /* ---- API: 校区楼栋静态表 ---- */
    if (p === '/api/campuses' && req.method === 'GET') {
      return json(res, 200, { ok: true, campuses: CAMPUSES });
    }

    /* ---- API: 空教室查询 ---- */
    if (p === '/api/query' && req.method === 'POST') {
      const { sid, aid, buildings, week, day, from = 1, to = 11 } = await readJson(req);
      const s = getSession(sid);
      if (!s) return json(res, 401, { ok: false, error: '登录已过期,请重新登录' });
      const bIds = Array.isArray(buildings) ? buildings.map(Number).filter(Boolean) : [];
      if (!bIds.length) return json(res, 400, { ok: false, error: '请至少选择一栋教学楼' });
      const wk = parseInt(week, 10);
      const dy = parseInt(day, 10);
      const f = Math.max(1, parseInt(from, 10) || 1);
      const t = Math.min(11, parseInt(to, 10) || 11);
      if (!wk || wk < 1 || wk > 25) return json(res, 400, { ok: false, error: '周次不正确' });
      if (!dy || dy < 1 || dy > 7) return json(res, 400, { ok: false, error: '星期不正确' });

      const results = await mapLimit(bIds, 3, async (bid) => {
        try {
          const { title, rooms } = await fetchBuildingSchedule(s.jar, aid, bid, wk, dy);
          for (const r of rooms) {
            r.freeInRange = r.occupied.every((o) => o < f || o > t);
          }
          return { buildingId: bid, title, rooms };
        } catch (e) {
          if (e.message === 'SESSION_EXPIRED') throw e;
          return { buildingId: bid, title: '', rooms: [], error: '查询失败' };
        }
      });
      return json(res, 200, { ok: true, semester: '', week: wk, day: dy, dayName: DAY_NAMES[dy], from: f, to: t, results });
    }

    /* ---- API: 退出 ---- */
    if (p === '/api/logout' && req.method === 'POST') {
      const { sid } = await readJson(req);
      if (sid) sessions.delete(sid);
      return json(res, 200, { ok: true });
    }

    /* ---- 静态文件(index.html 在仓库根目录,与 GitHub Pages 结构一致) ---- */
    let file = p === '/' ? '/index.html' : p;
    const safe = path.normalize(file).replace(/^(\.\.[/\\])+/, '');
    const full = path.join(__dirname, 'public', safe);
    if (!full.startsWith(path.join(__dirname, 'public'))) { res.writeHead(403); return res.end(); }
    if (fs.existsSync(full) && fs.statSync(full).isFile()) {
      const ext = path.extname(full).toLowerCase();
      res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream', ...res.__cors });
      return fs.createReadStream(full).pipe(res);
    }
    // 根目录的 index.html
    const rootIndex = path.join(__dirname, 'index.html');
    if (p === '/' || p === '/index.html') {
      if (fs.existsSync(rootIndex)) {
        res.writeHead(200, { 'Content-Type': MIME['.html'], ...res.__cors });
        return fs.createReadStream(rootIndex).pipe(res);
      }
    }
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not Found');
  } catch (e) {
    const msg = e && e.message === 'SESSION_EXPIRED' ? '登录已过期,请重新登录' : (e && e.message) || '服务器错误';
    const code = e && e.message === 'SESSION_EXPIRED' ? 401 : 500;
    json(res, code, { ok: false, error: msg });
  }
});

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of sessions) if (now - v.createdAt > SESSION_TTL) sessions.delete(k);
}, 60 * 1000).unref();

server.listen(PORT, HOST, () => {
  console.log(`空教室查询服务已启动: http://127.0.0.1:${PORT}`);
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] || []) {
      if (net.family === 'IPv4' && !net.internal) {
        console.log(`手机(同一Wi-Fi)可访问: http://${net.address}:${PORT}`);
      }
    }
  }
});
