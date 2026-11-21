/**
 * Auth.gs — autentikasi dan sesi.
 *
 * KONTRAK HASH DUA LAPIS
 *  Browser: key = hex( PBKDF2-HMAC-SHA256( password UTF-8, salt = byte dari hex clientSalt,
 *                      iterasi = CFG.PBKDF2_ITERATIONS, panjang 32 byte ) )   // Web Crypto
 *  Server tidak pernah menerima kata sandi asli, hanya "key" (64 hex).
 *  Server menyimpan passwordHash = HMAC-SHA256(pepper, "pw:" + userId + ":" + key).
 *
 * AKTIVASI AKUN: akun baru / hasil reset berstatus "pending" dan memiliki kode aktivasi sekali
 *  pakai (berlaku 24 jam). Pengguna membuat kata sandinya sendiri di browser.
 *
 * SESI: token acak; server hanya menyimpan HMAC token di CacheService. Pencabutan massal per
 *  pengguna memakai penanda "rev:<userId>". Cache bisa hilang lebih awal -> pengguna login ulang (aman).
 */

var CODE_ALPHABET_ = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // tanpa I, O, 0, 1
var MSG_LOGIN_GAGAL_ = 'Username atau kata sandi salah.';
var MSG_AKTIVASI_GAGAL_ = 'Kode aktivasi tidak valid atau sudah kedaluwarsa.';
var MSG_TERKUNCI_ = 'Terlalu banyak percobaan. Coba lagi beberapa menit lagi.';

function authError_(code, message) {
  var e = new Error(message);
  e.code = code; e.isAuth = true;
  return e;
}

function auth_findUser_(username) {
  var u = String(username || '').toLowerCase();
  var rows = db_readAll_('Users');
  for (var i = 0; i < rows.length; i++) if (rows[i].username.toLowerCase() === u) return rows[i];
  return null;
}

function auth_isUsername_(u) { return typeof u === 'string' && CFG.USERNAME_RE.test(u); }
function auth_isHex_(s, n) { return typeof s === 'string' && new RegExp('^[0-9a-f]{' + n + '}$').test(s); }

// ---------- Pembatasan percobaan ----------
function auth_throttleKey_(kind, who) {
  return 'thr:' + kind + ':' + hmacHex_('thr:' + String(who).toLowerCase().substring(0, 64)).substring(0, 32);
}
function auth_isLocked_(key) {
  var n = parseInt(CacheService.getScriptCache().get(key) || '0', 10);
  return n >= CFG.FAIL_MAX;
}
function auth_fail_(key) {
  var lock = LockService.getScriptLock();
  lock.waitLock(5000);
  try {
    var c = CacheService.getScriptCache();
    var n = parseInt(c.get(key) || '0', 10) + 1;
    c.put(key, String(n), CFG.FAIL_LOCK_SEC);
    return n;
  } finally { lock.releaseLock(); }
}
function auth_clearFail_(key) { CacheService.getScriptCache().remove(key); }

// ---------- Sesi ----------
function auth_createSession_(u) {
  var token = randomHex_(32), now = Date.now();
  var rev = parseInt(CacheService.getScriptCache().get('rev:' + u.userId) || '0', 10);
  var s = { u: u.userId, un: u.username, n: u.displayName, r: u.role, c: Math.max(now, rev + 1), e: now + CFG.SESSION_TTL_SEC * 1000 };   // c selalu lebih baru dari penanda pencabutan terakhir
  CacheService.getScriptCache().put('sess:' + hmacHex_('tok:' + token), JSON.stringify(s), CFG.SESSION_TTL_SEC);
  return { token: token, expiresAt: s.e };
}

function auth_revokeUser_(userId) {
  CacheService.getScriptCache().put('rev:' + userId, String(Date.now()), CFG.REVOKE_MARK_TTL_SEC);
  try { db_withLock_(function () { auth_revokeDevicesRaw_(userId); }); }   // semua perangkat yang diingat ikut dicabut
  catch (e) { console.error('cabut perangkat gagal (sheet Devices belum ada? jalankan setup()): ' + (e && e.message)); }
}

/**
 * Wajib dipanggil di backend untuk setiap operasi internal.
 * opts.roles: daftar peran yang diizinkan. opts.fresh: baca ulang status/peran dari sheet
 * (wajib untuk operasi admin dan operasi berisiko).
 */
function auth_requireSession_(token, opts) {
  opts = opts || {};
  var expired = authError_('SESI_BERAKHIR', 'Sesi berakhir. Silakan login lagi.');
  if (!auth_isHex_(token, 64)) throw expired;
  var raw = CacheService.getScriptCache().get('sess:' + hmacHex_('tok:' + token));
  if (!raw) throw expired;
  var s = JSON.parse(raw);
  if (Date.now() > s.e) throw expired;
  var rev = CacheService.getScriptCache().get('rev:' + s.u);
  if (rev && parseInt(rev, 10) >= s.c) throw expired;   // sesi yang dibuat pada milidetik yang sama dengan pencabutan dianggap sudah dicabut

  var user = { userId: s.u, username: s.un, displayName: s.n, role: s.r };
  if (opts.fresh) {
    var cur = db_findBy_('Users', 'userId', s.u);
    if (!cur || cur.accountStatus !== 'active') throw expired;
    user.role = cur.role; user.displayName = cur.displayName; user.username = cur.username;
  }
  if (opts.roles && opts.roles.indexOf(user.role) < 0) {
    throw authError_('DILARANG', 'Anda tidak berwenang melakukan tindakan ini.');
  }
  return user;
}

// ---------- Endpoint publik (dipanggil lewat dispatcher api) ----------
function auth_getSalt_(username) {
  var name = String(username || '').toLowerCase().substring(0, 64);
  var fake = hmacHex_('fake:' + name).substring(0, 32);   // salt palsu deterministik
  var salt = fake;
  if (auth_isUsername_(name)) {
    var u = auth_findUser_(name);
    if (u && u.accountStatus === 'active' && u.clientSalt) salt = u.clientSalt;
  }
  return { ok: true, salt: salt, iterations: CFG.PBKDF2_ITERATIONS };
}

function auth_login_(p) {
  var username = String((p && p.username) || '').toLowerCase();
  var key = (p && p.key) || '';
  var fail = { ok: false, code: 'LOGIN_GAGAL', message: MSG_LOGIN_GAGAL_ };
  if (!auth_isUsername_(username) || !auth_isHex_(key, 64)) return fail;

  var thr = auth_throttleKey_('login', username);
  if (auth_isLocked_(thr)) return { ok: false, code: 'TERKUNCI', message: MSG_TERKUNCI_ };

  var u = auth_findUser_(username);
  var given = hmacHex_('pw:' + (u ? u.userId : 'none') + ':' + key);
  var eq = constEq_(given, (u && u.passwordHash) || 'x');
  var ok = !!(u && u.accountStatus === 'active' && u.passwordHash && eq);

  if (!ok) {
    var n = auth_fail_(thr);
    if (u) audit_(u.userId, 'login', u.userId, n >= CFG.FAIL_MAX ? 'gagal_terkunci' : 'gagal');
    return fail;
  }
  auth_clearFail_(thr);
  var sess = auth_createSession_(u);
  db_updateById_('Users', u.userId, { lastLoginAt: nowIso_() });
  audit_(u.userId, 'login', u.userId, 'berhasil');
  var dev = null, denied = false;
  try {
    if (auth_isHex_(p.oldDevice, 64)) db_withLock_(function () { auth_revokeDevicesRaw_(u.userId, auth_devHash_(p.oldDevice)); });   // ganti token lama di HP yang sama
    if (p.remember === true) {
      dev = auth_newDevice_(u); denied = !dev;
      if (dev) audit_(u.userId, 'ingat_perangkat', u.userId, 'berhasil');
    }
  } catch (e) { console.error('ingat perangkat gagal: ' + (e && e.message)); dev = null; denied = true; }
  return { ok: true, token: sess.token, expiresAt: sess.expiresAt, device: dev, deviceDenied: denied,
           user: { userId: u.userId, username: u.username, displayName: u.displayName, role: u.role } };
}

function auth_logout_(token, p) {
  var s = auth_requireSession_(token);
  CacheService.getScriptCache().remove('sess:' + hmacHex_('tok:' + token));
  if (p && auth_isHex_(p.deviceToken, 64)) {   // keluar = lupakan perangkat ini (hanya milik akun sendiri)
    var h_ = auth_devHash_(p.deviceToken);
    try { db_withLock_(function () { auth_revokeDevicesRaw_(s.userId, h_); }); }
    catch (e) { console.error('cabut perangkat gagal: ' + (e && e.message)); }
  }
  audit_(s.userId, 'logout', s.userId, 'berhasil');
  return { ok: true };
}

function auth_activate_(p) {
  var fail = { ok: false, code: 'AKTIVASI_GAGAL', message: MSG_AKTIVASI_GAGAL_ };
  var username = String((p && p.username) || '').toLowerCase();
  var code = auth_normCode_(p && p.code);
  var salt = (p && p.salt) || '', key = (p && p.key) || '';
  if (!auth_isUsername_(username) || code.length !== 12 || !auth_isHex_(salt, 32) || !auth_isHex_(key, 64)) return fail;

  var thr = auth_throttleKey_('act', username);
  if (auth_isLocked_(thr)) return { ok: false, code: 'TERKUNCI', message: MSG_TERKUNCI_ };

  var activatedId = db_withLock_(function () {      // verifikasi + simpan atomik: kode benar-benar sekali pakai
    var u = auth_findUser_(username);
    if (!u || u.accountStatus !== 'pending' || !u.setupCodeHash) return null;
    var notExpired = Date.now() < Date.parse(u.setupCodeExpiresAt);
    var match = constEq_(hmacHex_('setup:' + u.userId + ':' + code), u.setupCodeHash);
    if (!notExpired || !match) return null;
    db_updateByIdRaw_('Users', u.userId, {
      clientSalt: salt, passwordHash: hmacHex_('pw:' + u.userId + ':' + key),
      setupCodeHash: '', setupCodeExpiresAt: '', accountStatus: 'active', updatedAt: nowIso_()
    });
    return u.userId;
  });

  if (!activatedId) { auth_fail_(thr); return fail; }
  auth_clearFail_(thr);
  auth_revokeUser_(activatedId);
  audit_(activatedId, 'aktivasi_akun', activatedId, 'berhasil');
  return { ok: true };
}

function auth_changePassword_(token, p) {
  var s = auth_requireSession_(token, { fresh: true });
  var oldKey = (p && p.oldKey) || '', newSalt = (p && p.newSalt) || '', newKey = (p && p.newKey) || '';
  if (!auth_isHex_(oldKey, 64) || !auth_isHex_(newSalt, 32) || !auth_isHex_(newKey, 64)) {
    return { ok: false, code: 'DATA_TIDAK_VALID', message: 'Data tidak valid.' };
  }
  var thr = auth_throttleKey_('chg', s.userId);
  if (auth_isLocked_(thr)) return { ok: false, code: 'TERKUNCI', message: MSG_TERKUNCI_ };

  var u = db_findBy_('Users', 'userId', s.userId);
  if (!constEq_(hmacHex_('pw:' + u.userId + ':' + oldKey), u.passwordHash || 'x')) {
    auth_fail_(thr);
    audit_(u.userId, 'ganti_sandi', u.userId, 'gagal');
    return { ok: false, code: 'SANDI_LAMA_SALAH', message: 'Kata sandi lama salah.' };
  }
  auth_clearFail_(thr);
  db_updateById_('Users', u.userId, {
    clientSalt: newSalt, passwordHash: hmacHex_('pw:' + u.userId + ':' + newKey), updatedAt: nowIso_()
  });
  auth_revokeUser_(u.userId);   // semua sesi berakhir, termasuk sesi ini
  audit_(u.userId, 'ganti_sandi', u.userId, 'berhasil');
  return { ok: true, message: 'Kata sandi diubah. Silakan login lagi.' };
}

// ---------- Dipakai Users.gs / Setup.gs (bukan endpoint publik) ----------
function auth_normCode_(c) { return String(c || '').toUpperCase().replace(/[^A-Z0-9]/g, ''); }

function auth_newSetupCode_() {
  var hex = randomHex_(12), out = '';
  for (var i = 0; i < 12; i++) {
    out += CODE_ALPHABET_.charAt(parseInt(hex.substr(i * 2, 2), 16) % 32);
    if (i % 4 === 3 && i < 11) out += '-';
  }
  return out;
}

// Membuat kode aktivasi sekali pakai, mengosongkan kata sandi lama, dan mencabut semua sesi.
// Mengembalikan kode (tampilkan SEKALI kepada admin; jangan disimpan/dilog).
function auth_issueSetupCode_(userId, actorId) {
  var cur = db_findBy_('Users', 'userId', userId);
  if (!cur) throw userError_('TIDAK_DITEMUKAN', 'Akun tidak ditemukan.');
  if (cur.accountStatus === 'disabled') {
    throw userError_('AKUN_NONAKTIF', 'Akun nonaktif. Aktifkan akun terlebih dahulu.');
  }
  var code = auth_newSetupCode_();
  db_updateById_('Users', userId, {
    accountStatus: 'pending', clientSalt: '', passwordHash: '',
    setupCodeHash: hmacHex_('setup:' + userId + ':' + auth_normCode_(code)),
    setupCodeExpiresAt: new Date(Date.now() + CFG.SETUP_CODE_TTL_MS).toISOString(),
    updatedAt: nowIso_()
  });
  auth_revokeUser_(userId);
  audit_(actorId, 'terbit_kode_aktivasi', userId, 'berhasil');
  return code;
}

// Wajib untuk setiap operasi admin: peran dan status dibaca ulang dari sheet (bukan dari sesi).
function auth_requireAdmin_(token) {
  return auth_requireSession_(token, { roles: ['admin'], fresh: true });
}

// ====================== PERANGKAT DIINGAT ("ingat saya") ======================
// Token perangkat: 256-bit acak, hanya HMAC-nya yang disimpan (sheet Devices). Berotasi setiap dipakai;
// pemakaian ulang token lama setelah masa tenggang dianggap pencurian dan mencabut SEMUA perangkat akun itu.
// Dicabut otomatis saat: ganti/reset kata sandi, akun dinonaktifkan, peran diubah, atau pengguna memilih keluar.
function auth_policy_(role) {
  var idle = role === 'admin' ? CFG.REMEMBER_ADMIN_IDLE_DAYS : CFG.REMEMBER_MEMBER_IDLE_DAYS;
  var max = role === 'admin' ? CFG.REMEMBER_ADMIN_MAX_DAYS : CFG.REMEMBER_MEMBER_MAX_DAYS;
  return (idle > 0 && max > 0) ? { idleMs: idle * 86400000, maxMs: max * 86400000, idleDays: idle } : null;
}
function auth_devHash_(token) { return hmacHex_('dev:' + token); }
function auth_isLockedN_(key, n) { return parseInt(CacheService.getScriptCache().get(key) || '0', 10) >= n; }

// Tanpa kunci: panggil hanya di dalam db_withLock_. onlyHash: batasi ke satu perangkat.
function auth_revokeDevicesRaw_(userId, onlyHash) {
  var n = 0;
  db_readAll_('Devices').forEach(function (r) {
    if (r.userId === userId && r.status === 'aktif' && (!onlyHash || constEq_(r.tokenHash, onlyHash) || (r.prevHash && constEq_(r.prevHash, onlyHash)))) {
      db_updateByIdRaw_('Devices', r.deviceId, { status: 'dicabut' }); n++;
    }
  });
  return n;
}

function auth_newDevice_(user) {
  var pol = auth_policy_(user.role);
  if (!pol) return null;
  var token = randomHex_(32), now = Date.now(), maxAt = now + pol.maxMs;
  var row = { deviceId: newId_('V'), userId: user.userId, tokenHash: auth_devHash_(token), prevHash: '', prevUntil: '',
    createdAt: new Date(now).toISOString(), lastUsedAt: new Date(now).toISOString(),
    expiresAt: new Date(Math.min(now + pol.idleMs, maxAt)).toISOString(), maxExpiresAt: new Date(maxAt).toISOString(), status: 'aktif' };
  db_withLock_(function () {
    var act = db_readAll_('Devices').filter(function (r) { return r.userId === user.userId && r.status === 'aktif'; })
      .sort(function (x, y) { return x.createdAt < y.createdAt ? -1 : 1; });
    while (act.length >= CFG.REMEMBER_MAX_DEVICES) db_updateByIdRaw_('Devices', act.shift().deviceId, { status: 'dicabut' });
    db_appendRaw_('Devices', row);
  });
  return { token: token, expiresAt: row.expiresAt };
}

function auth_userForDevice_(row) {
  var u = db_findBy_('Users', 'userId', row.userId);
  return (u && u.accountStatus === 'active' && auth_policy_(u.role)) ? u : null;
}

// Publik: menukar token perangkat dengan sesi baru (tanpa kata sandi).
function auth_resume_(p) {
  var fail = { ok: false, code: 'RESUME_GAGAL', message: 'Sesi perangkat berakhir. Silakan login.' };
  var tok = p && p.deviceToken;
  if (!auth_isHex_(tok, 64)) return fail;
  var thr = 'thr:resume:all';
  if (auth_isLockedN_(thr, CFG.RESUME_FAIL_MAX)) return { ok: false, code: 'TERKUNCI', message: MSG_TERKUNCI_ };
  var hash = auth_devHash_(tok), now = Date.now(), out;
  try {
    out = db_withLock_(function () {
      var rows = db_readAll_('Devices'), cur = null, prev = null, i;
      for (i = 0; i < rows.length; i++) {   // bandingkan semua baris (waktu tetap terhadap isi)
        var m1 = constEq_(rows[i].tokenHash, hash), m2 = !!rows[i].prevHash && constEq_(rows[i].prevHash, hash);
        if (m1 && rows[i].status === 'aktif') cur = rows[i];
        if (m2) prev = rows[i];
      }
      if (!cur && prev && prev.status === 'aktif') {
        var u0 = auth_userForDevice_(prev);
        if (u0 && now <= Date.parse(prev.prevUntil)) return { ok: true, user: u0, token: null };   // tab lain baru merotasi: terima tanpa token baru
        auth_revokeDevicesRaw_(prev.userId);   // token lama dipakai ulang setelah masa tenggang: curiga dicuri
        return { theft: prev.userId };
      }
      if (!cur) return { fail: true };
      var u = auth_userForDevice_(cur), exp = Date.parse(cur.expiresAt), maxExp = Date.parse(cur.maxExpiresAt);
      if (!u || !(now < exp) || !(now < maxExp)) { db_updateByIdRaw_('Devices', cur.deviceId, { status: 'dicabut' }); return { fail: true }; }
      var pol = auth_policy_(u.role), newTok = randomHex_(32), newExp = new Date(Math.min(now + pol.idleMs, maxExp)).toISOString();
      db_updateByIdRaw_('Devices', cur.deviceId, { prevHash: hash, prevUntil: new Date(now + CFG.REMEMBER_GRACE_SEC * 1000).toISOString(),
        tokenHash: auth_devHash_(newTok), lastUsedAt: new Date(now).toISOString(), expiresAt: newExp });
      return { ok: true, user: u, token: newTok, expiresAt: newExp };
    });
  } catch (e) { console.error('lanjut sesi gagal: ' + (e && e.message)); return fail; }
  if (out.theft) {
    auth_revokeUser_(out.theft);
    audit_(out.theft, 'perangkat_dicabut_curiga', out.theft, 'token_lama_dipakai_ulang');
    auth_fail_(thr); return fail;
  }
  if (!out.ok) { auth_fail_(thr); return fail; }
  var sess = auth_createSession_(out.user), u2 = out.user;
  return { ok: true, token: sess.token, expiresAt: sess.expiresAt,
           device: out.token ? { token: out.token, expiresAt: out.expiresAt } : null,
           user: { userId: u2.userId, username: u2.username, displayName: u2.displayName, role: u2.role } };
}

function auth_devices_(token, p) {
  var s = auth_requireSession_(token, { fresh: true }), cur = auth_isHex_(p && p.deviceToken, 64) ? auth_devHash_(p.deviceToken) : '';
  var pol = auth_policy_(s.role), list = [];
  try {
    db_readAll_('Devices').forEach(function (r) {
      if (r.userId === s.userId && r.status === 'aktif' && Date.now() < Date.parse(r.expiresAt)) {
        list.push({ createdAt: r.createdAt, lastUsedAt: r.lastUsedAt, expiresAt: r.expiresAt, current: !!cur && (constEq_(r.tokenHash, cur) || (!!r.prevHash && constEq_(r.prevHash, cur))) });
      }
    });
  } catch (e) { console.error('daftar perangkat gagal: ' + (e && e.message)); }
  return { ok: true, devices: list, enabled: !!pol, idleDays: pol ? pol.idleDays : 0 };
}

// "Keluar dari semua perangkat": cabut semua token perangkat dan semua sesi akun ini.
function auth_revokeDevices_(token, p) {
  var s = auth_requireSession_(token, { fresh: true });
  auth_revokeUser_(s.userId);
  audit_(s.userId, 'cabut_perangkat', s.userId, 'semua');
  return { ok: true };
}
