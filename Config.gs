/**
 * Config.gs — konfigurasi, skema sheet, dan utilitas umum.
 * Rahasia (SPREADSHEET_ID, FOLDER_ID, PEPPER) disimpan di Script Properties, BUKAN di file ini.
 * Fungsi berakhiran "_" bersifat privat: tidak bisa dipanggil dari browser lewat google.script.run.
 */
var CFG = {
  APP_NAME: 'OSIS Archive',
  SESSION_TTL_SEC: 2 * 60 * 60,        // sesi 2 jam
  REVOKE_MARK_TTL_SEC: 6 * 60 * 60,    // harus >= SESSION_TTL_SEC (batas maks CacheService 6 jam)
  SETUP_CODE_TTL_MS: 24 * 60 * 60 * 1000,
  FAIL_MAX: 5,                         // percobaan gagal sebelum dikunci
  FAIL_LOCK_SEC: 15 * 60,              // lama kunci setelah gagal berulang
  PBKDF2_ITERATIONS: 600000,           // dipakai browser (Web Crypto), bukan server
  USERNAME_RE: /^[a-z0-9._-]{3,30}$/,
  ROLES: ['admin', 'anggota'],

  // ---- "Ingat saya di perangkat ini" (token perangkat; 0 = fitur dimatikan untuk peran itu) ----
  REMEMBER_MEMBER_IDLE_DAYS: 30,   // kedaluwarsa jika tidak dipakai selama ini
  REMEMBER_MEMBER_MAX_DAYS: 90,    // batas mutlak sejak dibuat, walau terus dipakai
  REMEMBER_ADMIN_IDLE_DAYS: 0,     // admin TIDAK diingat (hak istimewa tinggi). Untuk mengaktifkan: mis. 7 dan 30
  REMEMBER_ADMIN_MAX_DAYS: 0,
  REMEMBER_GRACE_SEC: 120,         // token lama masih diterima sebentar setelah rotasi (dua tab membuka bersamaan)
  REMEMBER_MAX_DEVICES: 5,         // maksimal perangkat diingat per akun; yang tertua dicabut
  RESUME_FAIL_MAX: 300,            // kegagalan lanjut-sesi (seluruh aplikasi) sebelum dikunci sementara

  // ---- Upload & dokumen ----
  MAX_FILE_BYTES: 10 * 1024 * 1024,    // 10 MB (naik = risiko batas waktu/ukuran transfer Apps Script)
  MAX_FILENAME_LEN: 120,
  UPLOAD_MAX_PER_HOUR: 20,             // batas upload per pengguna per jam
  UPLOAD_STALE_MS: 2 * 60 * 1000,      // upload "memproses" lebih lama dari ini boleh diambil alih (coba ulang)
  DUP_PENDING_MS: 10 * 60 * 1000,      // upload yang masih memproses dianggap duplikat selama ini
  PAGE_SIZE_DEFAULT: 20,
  PAGE_SIZE_MAX: 50,
  // Jenis file yang diizinkan (ubah di sini). zipDir = folder wajib di dalam paket Office.
  ALLOWED_TYPES: {
    pdf:  { mime: 'application/pdf' },
    docx: { mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', zipDir: 'word/' },
    xlsx: { mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', zipDir: 'xl/' },
    pptx: { mime: 'application/vnd.openxmlformats-officedocument.presentationml.presentation', zipDir: 'ppt/' },
    jpg:  { mime: 'image/jpeg' },
    jpeg: { mime: 'image/jpeg' },
    png:  { mime: 'image/png' }
  }
};

// Kolom pertama setiap sheet adalah ID unik.
var SCHEMA = {
  Users: ['userId', 'username', 'displayName', 'role', 'accountStatus', 'clientSalt', 'passwordHash',
          'setupCodeHash', 'setupCodeExpiresAt', 'createdAt', 'updatedAt', 'lastLoginAt'],
  Documents: ['documentId', 'driveFileId', 'title', 'originalFileName', 'description', 'categoryId', 'year',
              'activityName', 'keywords', 'uploadedBy', 'uploadedAt', 'mimeType', 'fileSize', 'fileStatus',
              'contentHash', 'requestId', 'updatedAt', 'documentDate'],
  Categories: ['categoryId', 'categoryName', 'description', 'activeStatus', 'createdAt'],
  AuditLogs: ['logId', 'actorId', 'action', 'targetId', 'timestamp', 'result'],
  Devices: ['deviceId', 'userId', 'tokenHash', 'prevHash', 'prevUntil', 'createdAt', 'lastUsedAt', 'expiresAt', 'maxExpiresAt', 'status']
};

var DEFAULT_CATEGORIES = [
  'Surat Masuk', 'Surat Keluar', 'Proposal Kegiatan', 'Laporan Pertanggungjawaban', 'Notulen Rapat',
  'Program Kerja', 'Administrasi Kepengurusan', 'Dokumentasi Kegiatan', 'Inventaris',
  'Peraturan dan Pedoman', 'Arsip Pengurus Sebelumnya', 'Template Dokumen', 'Lainnya'
];

// ---------- Script Properties ----------
function cfgGet_(key) {
  var v = PropertiesService.getScriptProperties().getProperty(key);
  if (!v) throw new Error('Konfigurasi belum diatur: ' + key + '. Ikuti panduan setup().');
  return v;
}
var PEPPER_CACHE_ = null;
function cfgPepper_() {
  if (!PEPPER_CACHE_) PEPPER_CACHE_ = cfgGet_('PEPPER');
  return PEPPER_CACHE_;
}

// ---------- Utilitas umum ----------
function nowIso_() { return new Date(Date.now()).toISOString(); }

function hex_(bytes) {
  var s = '';
  for (var i = 0; i < bytes.length; i++) {
    var b = (bytes[i] + 256) % 256;
    s += (b < 16 ? '0' : '') + b.toString(16);
  }
  return s;
}

// HMAC-SHA256 dengan pepper rahasia server. Selalu beri awalan domain ("pw:", "tok:", ...).
function hmacHex_(message) {
  return hex_(Utilities.computeHmacSha256Signature(String(message), cfgPepper_()));
}

// Perbandingan string dengan waktu relatif tetap.
function constEq_(a, b) {
  a = String(a); b = String(b);
  var len = Math.max(a.length, b.length), diff = a.length ^ b.length;
  for (var i = 0; i < len; i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}

// Apps Script tidak mendokumentasikan CSPRNG. Kita campur beberapa UUID v4 + waktu
// lalu lewatkan HMAC berkunci pepper rahasia, sehingga keluaran tidak dapat ditebak
// tanpa mengetahui pepper.
function randomHex_(nBytes) {
  var seed = '';
  for (var i = 0; i < 4; i++) seed += Utilities.getUuid();
  seed += ':' + Date.now() + ':' + Math.random();
  var out = '', ctr = 0;
  while (out.length < nBytes * 2) {
    out += hmacHex_('rnd:' + (ctr++) + ':' + seed + ':' + Utilities.getUuid());
  }
  return out.substring(0, nBytes * 2);
}

function newId_(prefix) { return prefix + '-' + randomHex_(6); }
