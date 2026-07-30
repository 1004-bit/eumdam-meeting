const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '127.0.0.1';
const ROOT = path.join(__dirname, 'public');
const db = new DatabaseSync(path.join(__dirname, 'community.db'));

db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS likes (
    post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (post_id, user_id)
  );
  CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id, created_at);
  CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
`);

if (db.prepare('SELECT COUNT(*) AS count FROM posts').get().count === 0) {
  const now = Date.now();
  const insertUser = db.prepare('INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)');
  const insertPost = db.prepare('INSERT INTO posts (user_id, category, title, content, created_at) VALUES (?, ?, ?, ?, ?)');
  const insertComment = db.prepare('INSERT INTO comments (post_id, user_id, content, created_at) VALUES (?, ?, ?, ?)');
  const insertLike = db.prepare('INSERT INTO likes (post_id, user_id) VALUES (?, ?)');
  db.exec('BEGIN');
  try {
    const users = ['여름밤', '모과', '파란새'].map((name, index) => Number(insertUser.run(name, 'seed-disabled', now - index * 1000).lastInsertRowid));
    const first = Number(insertPost.run(users[0], '오늘', '요즘 나를 웃게 만든 사소한 일', '퇴근길에 만난 강아지가 제 신발 끈을 한참 바라봤어요. 별일 아닌데 하루 종일 생각나더라고요. 여러분을 최근에 웃게 만든 순간은 무엇인가요?', now - 24 * 60 * 1000).lastInsertRowid);
    const second = Number(insertPost.run(users[1], '취향', '한 곡만 반복해서 듣는 사람 있나요?', '좋아하는 노래가 생기면 질릴 때까지 한 곡만 듣는 편이에요. 이번 주에는 잔잔한 기타 음악에 빠졌습니다. 지금 반복 중인 노래를 나눠주세요.', now - 2 * 60 * 60 * 1000).lastInsertRowid);
    insertPost.run(users[2], '질문', '혼자 보내는 주말을 잘 쓰는 방법', '예정 없는 주말이 생겼어요. 집에서 쉬는 것도 좋지만 기억에 남는 하루를 만들고 싶습니다. 혼자서 하기 좋은 활동이 있다면 추천해주세요.', now - 5 * 60 * 60 * 1000);
    insertComment.run(first, users[1], '버스에서 아기가 손을 흔들어줬을 때요. 저도 모르게 같이 웃었어요.', now - 12 * 60 * 1000);
    insertComment.run(second, users[2], '저도 그래요. 요즘은 wave to earth 노래를 계속 듣고 있어요.', now - 60 * 60 * 1000);
    insertLike.run(first, users[1]);
    insertLike.run(first, users[2]);
    insertLike.run(second, users[0]);
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

function json(res, status, data, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(JSON.stringify(data));
}

function parseCookies(req) {
  return Object.fromEntries((req.headers.cookie || '').split(';').filter(Boolean).map(part => {
    const index = part.indexOf('=');
    return [part.slice(0, index).trim(), decodeURIComponent(part.slice(index + 1))];
  }));
}

function currentUser(req) {
  const token = parseCookies(req).nook_session;
  if (!token) return null;
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  return db.prepare(`SELECT users.id, users.username FROM sessions JOIN users ON users.id = sessions.user_id WHERE sessions.token_hash = ? AND sessions.expires_at > ?`).get(tokenHash, Date.now()) || null;
}

function requireUser(req, res) {
  const user = currentUser(req);
  if (!user) json(res, 401, { error: '로그인이 필요해요.' });
  return user;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 1024 * 1024) reject(new Error('요청이 너무 커요.'));
    });
    req.on('end', () => {
      try { resolve(body ? JSON.parse(body) : {}); } catch { reject(new Error('잘못된 요청이에요.')); }
    });
    req.on('error', reject);
  });
}

function passwordHash(password, salt = crypto.randomBytes(16).toString('hex')) {
  return `${salt}:${crypto.scryptSync(password, salt, 64).toString('hex')}`;
}

function passwordMatches(password, stored) {
  const [salt, hash] = stored.split(':');
  if (!salt || !hash) return false;
  const actual = crypto.scryptSync(password, salt, 64);
  const expected = Buffer.from(hash, 'hex');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function createSession(res, userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  const expires = Date.now() + 30 * 24 * 60 * 60 * 1000;
  db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(Date.now());
  db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)').run(crypto.createHash('sha256').update(token).digest('hex'), userId, expires);
  return { 'Set-Cookie': `nook_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000` };
}

function listPosts(userId = 0) {
  return db.prepare(`
    SELECT posts.id, posts.category, posts.title, posts.content, posts.created_at AS createdAt,
      users.id AS authorId, users.username AS author,
      (SELECT COUNT(*) FROM likes WHERE likes.post_id = posts.id) AS likeCount,
      (SELECT COUNT(*) FROM comments WHERE comments.post_id = posts.id) AS commentCount,
      EXISTS(SELECT 1 FROM likes WHERE likes.post_id = posts.id AND likes.user_id = ?) AS liked
    FROM posts JOIN users ON users.id = posts.user_id
    ORDER BY posts.created_at DESC
  `).all(userId);
}

async function api(req, res, url) {
  const method = req.method;
  if (method === 'GET' && url.pathname === '/api/me') return json(res, 200, { user: currentUser(req) });
  if (method === 'POST' && url.pathname === '/api/signup') {
    const { username = '', password = '' } = await readBody(req);
    const cleanName = String(username).trim();
    if (!/^[A-Za-z0-9가-힣_]{2,20}$/.test(cleanName)) return json(res, 400, { error: '아이디는 한글, 영문, 숫자로 2~20자여야 해요.' });
    if (String(password).length < 6 || String(password).length > 100) return json(res, 400, { error: '비밀번호는 6자 이상이어야 해요.' });
    try {
      const result = db.prepare('INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)').run(cleanName, passwordHash(password), Date.now());
      const user = { id: Number(result.lastInsertRowid), username: cleanName };
      return json(res, 201, { user }, createSession(res, user.id));
    } catch (error) {
      if (String(error.message).includes('UNIQUE')) return json(res, 409, { error: '이미 사용 중인 아이디예요.' });
      throw error;
    }
  }
  if (method === 'POST' && url.pathname === '/api/login') {
    const { username = '', password = '' } = await readBody(req);
    const user = db.prepare('SELECT id, username, password_hash FROM users WHERE username = ? COLLATE NOCASE').get(String(username).trim());
    if (!user || !passwordMatches(String(password), user.password_hash)) return json(res, 401, { error: '아이디 또는 비밀번호가 맞지 않아요.' });
    return json(res, 200, { user: { id: user.id, username: user.username } }, createSession(res, user.id));
  }
  if (method === 'POST' && url.pathname === '/api/logout') {
    const token = parseCookies(req).nook_session;
    if (token) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(crypto.createHash('sha256').update(token).digest('hex'));
    return json(res, 200, { ok: true }, { 'Set-Cookie': 'nook_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0' });
  }
  if (method === 'GET' && url.pathname === '/api/posts') return json(res, 200, { posts: listPosts(currentUser(req)?.id) });
  if (method === 'POST' && url.pathname === '/api/posts') {
    const user = requireUser(req, res);
    if (!user) return;
    const { category = '', title = '', content = '' } = await readBody(req);
    if (!['오늘', '취향', '질문', '고민', '정보', '모임'].includes(category)) return json(res, 400, { error: '올바른 주제를 선택해주세요.' });
    if (!String(title).trim() || String(title).trim().length > 80) return json(res, 400, { error: '제목은 1~80자로 입력해주세요.' });
    if (!String(content).trim() || String(content).trim().length > 5000) return json(res, 400, { error: '내용은 1~5000자로 입력해주세요.' });
    const result = db.prepare('INSERT INTO posts (user_id, category, title, content, created_at) VALUES (?, ?, ?, ?, ?)').run(user.id, category, String(title).trim(), String(content).trim(), Date.now());
    return json(res, 201, { id: Number(result.lastInsertRowid) });
  }
  const postMatch = url.pathname.match(/^\/api\/posts\/(\d+)$/);
  if (method === 'GET' && postMatch) {
    const post = listPosts(currentUser(req)?.id).find(item => item.id === Number(postMatch[1]));
    if (!post) return json(res, 404, { error: '게시글을 찾을 수 없어요.' });
    const comments = db.prepare(`SELECT comments.id, comments.content, comments.created_at AS createdAt, users.id AS authorId, users.username AS author FROM comments JOIN users ON users.id = comments.user_id WHERE comments.post_id = ? ORDER BY comments.created_at`).all(post.id);
    return json(res, 200, { post: { ...post, comments } });
  }
  if (method === 'DELETE' && postMatch) {
    const user = requireUser(req, res);
    if (!user) return;
    const result = db.prepare('DELETE FROM posts WHERE id = ? AND user_id = ?').run(Number(postMatch[1]), user.id);
    return result.changes ? json(res, 200, { ok: true }) : json(res, 403, { error: '본인의 게시글만 삭제할 수 있어요.' });
  }
  const likeMatch = url.pathname.match(/^\/api\/posts\/(\d+)\/like$/);
  if (method === 'POST' && likeMatch) {
    const user = requireUser(req, res);
    if (!user) return;
    const postId = Number(likeMatch[1]);
    if (!db.prepare('SELECT id FROM posts WHERE id = ?').get(postId)) return json(res, 404, { error: '게시글을 찾을 수 없어요.' });
    const existing = db.prepare('SELECT 1 FROM likes WHERE post_id = ? AND user_id = ?').get(postId, user.id);
    if (existing) db.prepare('DELETE FROM likes WHERE post_id = ? AND user_id = ?').run(postId, user.id);
    else db.prepare('INSERT INTO likes (post_id, user_id) VALUES (?, ?)').run(postId, user.id);
    return json(res, 200, { liked: !existing });
  }
  const commentsMatch = url.pathname.match(/^\/api\/posts\/(\d+)\/comments$/);
  if (method === 'POST' && commentsMatch) {
    const user = requireUser(req, res);
    if (!user) return;
    const { content = '' } = await readBody(req);
    if (!String(content).trim() || String(content).trim().length > 500) return json(res, 400, { error: '댓글은 1~500자로 입력해주세요.' });
    const postId = Number(commentsMatch[1]);
    if (!db.prepare('SELECT id FROM posts WHERE id = ?').get(postId)) return json(res, 404, { error: '게시글을 찾을 수 없어요.' });
    const result = db.prepare('INSERT INTO comments (post_id, user_id, content, created_at) VALUES (?, ?, ?, ?)').run(postId, user.id, String(content).trim(), Date.now());
    return json(res, 201, { id: Number(result.lastInsertRowid) });
  }
  const commentMatch = url.pathname.match(/^\/api\/comments\/(\d+)$/);
  if (method === 'DELETE' && commentMatch) {
    const user = requireUser(req, res);
    if (!user) return;
    const result = db.prepare('DELETE FROM comments WHERE id = ? AND user_id = ?').run(Number(commentMatch[1]), user.id);
    return result.changes ? json(res, 200, { ok: true }) : json(res, 403, { error: '본인의 댓글만 삭제할 수 있어요.' });
  }
  return json(res, 404, { error: '요청한 API를 찾을 수 없어요.' });
}

function staticFile(res, pathname) {
  const requested = pathname === '/' ? 'index.html' : pathname.slice(1);
  const filePath = path.resolve(ROOT, requested);
  if (!filePath.startsWith(ROOT) || !fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    return json(res, 404, { error: '페이지를 찾을 수 없어요.' });
  }
  const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml' };
  res.writeHead(200, { 'Content-Type': types[path.extname(filePath)] || 'application/octet-stream', 'X-Content-Type-Options': 'nosniff' });
  fs.createReadStream(filePath).pipe(res);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  try {
    if (url.pathname.startsWith('/api/')) await api(req, res, url);
    else if (req.method === 'GET') staticFile(res, url.pathname);
    else json(res, 405, { error: '허용되지 않은 요청이에요.' });
  } catch (error) {
    console.error(error);
    if (!res.headersSent) json(res, 500, { error: error.message || '서버 오류가 발생했어요.' });
  }
});

server.listen(PORT, HOST, () => console.log(`Nook community listening on http://${HOST}:${PORT}`));
