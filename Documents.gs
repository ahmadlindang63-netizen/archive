/**
 * Documents.gs — arsip dokumen: upload, pencarian, buka, ubah metadata, hapus (arsip), pemeriksaan integritas.
 *
 * Status file (fileStatus): memproses | tersedia | gagal | hilang | dihapus
 * Upload tiga fase agar konsisten:
 *   1) (terkunci) klaim: periksa requestId/duplikat/batas, catat baris "memproses"
 *   2) (tanpa kunci) simpan file ke Drive dengan nama deterministik <documentId>__<nama>
 *   3) (terkunci) ubah baris menjadi "tersedia", lalu baca ulang untuk memastikan
 * Pesan sukses HANYA dikirim setelah fase 3 terverifikasi. Coba ulang dengan requestId yang SAMA
 * memulihkan upload tanpa membuat file ganda. File di Drive tidak pernah dihapus otomatis.
 */

// ---------- Pembantu ----------
function docs_maps_() {
  var users = {}, cats = {};
  db_readAll_('Users').forEach(function (u) { users[u.userId] = u.displayName; });
  db_readAll_('Categories').forEach(function (c) { cats[c.categoryId] = c.categoryName; });
  return { users: users, cats: cats };
}

function docs_ext_(name) {
  var i = String(name).lastIndexOf('.');
  var e = i > 0 ? String(name).substring(i + 1).toLowerCase() : '';
  return e === 'jpeg' ? 'jpg' : e;
}

function docs_public_(r, maps) {
  return {
    documentId: r.documentId, title: r.title, originalFileName: r.originalFileName, description: r.description,
    categoryId: r.categoryId, categoryName: maps.cats[r.categoryId] || '', year: Number(r.year) || r.year,
    activityName: r.activityName, keywords: r.keywords, documentDate: r.documentDate,
    uploadedBy: r.uploadedBy, uploaderName: maps.users[r.uploadedBy] || '(akun tidak ditemukan)',
    uploadedAt: r.uploadedAt, updatedAt: r.updatedAt, mimeType: r.mimeType, fileSize: Number(r.fileSize) || 0,
    fileStatus: r.fileStatus, fileType: docs_ext_(r.originalFileName)
  };
}

function docs_age_(iso) { return Date.now() - Date.parse(iso); }

// Metadata dari payload. currentCategoryId: kategori lama yang boleh dipertahankan walau sudah nonaktif.
function docs_validateMeta_(p, currentCategoryId) {
  var title = v_text_(p.title, 'Judul', { required: true, min: 3, max: 150 });
  var categoryId = v_id_(p.categoryId, 'Kategori');
  var cat = db_findBy_('Categories', 'categoryId', categoryId);
  if (!cat || (cat.activeStatus !== 'active' && categoryId !== currentCategoryId)) {
    throw userError_('KATEGORI_TIDAK_VALID', 'Kategori tidak valid atau sudah nonaktif.');
  }
  return {
    title: title, categoryId: categoryId, year: String(v_year_(p.year)),
    activityName: v_text_(p.activityName, 'Kegiatan', { max: 100 }),
    description: v_text_(p.description, 'Deskripsi', { max: 500, multiline: true }),
    keywords: v_keywords_(p.keywords), documentDate: v_date_(p.documentDate)
  };
}

function docs_opt_(v) { return (v === undefined || v === null || v === '') ? undefined : v; }

// ---------- Upload ----------
function docs_upload_(token, p) {
  var user = auth_requireSession_(token, { fresh: true });
  var requestId = v_requestId_(p.requestId);
  var meta = docs_validateMeta_(p, null);
  var f = v_file_(p);

  var claim = db_withLock_(function () {
    var rows = db_readAll_('Documents'), now = Date.now(), existing = null, i;
    for (i = 0; i < rows.length; i++) if (rows[i].requestId === requestId) existing = rows[i];
    if (existing) {
      if (existing.uploadedBy !== user.userId || existing.contentHash !== f.hash) {
        throw userError_('DATA_TIDAK_VALID', 'Permintaan tidak valid. Muat ulang halaman lalu coba lagi.');
      }
      if (existing.fileStatus === 'tersedia') return { state: 'done', row: existing };
      if (existing.fileStatus === 'memproses' && docs_age_(existing.updatedAt) < CFG.UPLOAD_STALE_MS) return { state: 'busy' };
      if (existing.fileStatus !== 'memproses' && existing.fileStatus !== 'gagal') {
        throw userError_('DATA_TIDAK_VALID', 'Permintaan tidak valid. Muat ulang halaman lalu coba lagi.');
      }
      var patch = JSON.parse(JSON.stringify(meta));
      patch.fileStatus = 'memproses'; patch.updatedAt = nowIso_();
      db_updateByIdRaw_('Documents', existing.documentId, patch);
      return { state: 'claimed', documentId: existing.documentId };
    }
    for (i = 0; i < rows.length; i++) {
      var r = rows[i];
      if (r.contentHash === f.hash && (r.fileStatus === 'tersedia' ||
          (r.fileStatus === 'memproses' && docs_age_(r.updatedAt) < CFG.DUP_PENDING_MS))) {
        throw userError_('DUPLIKAT_FILE', r.fileStatus === 'tersedia'
          ? 'File ini diduga duplikat dari dokumen "' + r.title + '" yang sudah ada di arsip.'
          : 'File yang sama sedang diunggah. Tunggu sebentar.');
      }
    }
    var cutoff = now - 3600000, cnt = 0;
    rows.forEach(function (r) { if (r.uploadedBy === user.userId && Date.parse(r.uploadedAt) > cutoff) cnt++; });
    if (cnt >= CFG.UPLOAD_MAX_PER_HOUR) {
      throw userError_('BATAS_UPLOAD', 'Batas upload ' + CFG.UPLOAD_MAX_PER_HOUR + ' file per jam tercapai. Coba lagi nanti.');
    }
    var doc = JSON.parse(JSON.stringify(meta)), id = newId_('D');
    doc.documentId = id; doc.driveFileId = ''; doc.originalFileName = f.name; doc.uploadedBy = user.userId;
    doc.uploadedAt = nowIso_(); doc.mimeType = f.mime; doc.fileSize = String(f.size); doc.fileStatus = 'memproses';
    doc.contentHash = f.hash; doc.requestId = requestId; doc.updatedAt = doc.uploadedAt;
    db_appendRaw_('Documents', doc);
    return { state: 'claimed', documentId: id };
  });

  var maps = docs_maps_();
  if (claim.state === 'done') return { ok: true, alreadySaved: true, document: docs_public_(claim.row, maps) };
  if (claim.state === 'busy') return { ok: false, code: 'SEDANG_DIPROSES', message: 'Upload sedang diproses. Tunggu sebentar, jangan tekan tombol lagi.' };

  var documentId = claim.documentId, driveName = documentId + '__' + f.name, fileId;
  try {   // fase 2
    var found = ds_findByName_(driveName, f.size);
    fileId = found ? found.getId() : ds_create_(f.bytes, f.mime, driveName, documentId);
  } catch (e) {
    try { db_updateById_('Documents', documentId, { fileStatus: 'gagal', updatedAt: nowIso_() }); } catch (e2) {}
    audit_(user.userId, 'unggah_dokumen', documentId, 'gagal_drive');
    if (e && e.isUser) return { ok: false, code: e.code, message: e.message, retry: false };
    console.error('upload drive gagal: ' + (e && e.message));
    return { ok: false, code: 'UPLOAD_GAGAL', message: 'Upload gagal dan dapat dicoba kembali.', retry: true };
  }
  try {   // fase 3
    db_updateById_('Documents', documentId, { driveFileId: fileId, fileStatus: 'tersedia', updatedAt: nowIso_() });
    var chk = db_findBy_('Documents', 'documentId', documentId);
    if (!chk || chk.fileStatus !== 'tersedia' || chk.driveFileId !== fileId) throw new Error('verifikasi metadata gagal');
    audit_(user.userId, 'unggah_dokumen', documentId, 'berhasil');
    return { ok: true, document: docs_public_(chk, maps) };
  } catch (e) {
    try { db_updateById_('Documents', documentId, { driveFileId: fileId, fileStatus: 'gagal', updatedAt: nowIso_() }); } catch (e2) {}
    console.error('upload metadata gagal: ' + (e && e.message));
    audit_(user.userId, 'unggah_dokumen', documentId, 'gagal_metadata');
    return { ok: false, code: 'METADATA_GAGAL_SIMPAN', retry: true,
      message: 'File sudah masuk Drive tetapi pencatatan gagal. Kirim ulang file yang sama; sistem memulihkannya tanpa membuat file ganda.' };
  }
}

// ---------- Pencarian ----------
function docs_terms_(q) {
  if (q === undefined) return [];
  if (typeof q !== 'string' || q.length > 200) throw userError_('DATA_TIDAK_VALID', 'Kata pencarian tidak valid.');
  return q.toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(function (t) { return t.length >= 2 || /^\d$/.test(t); }).slice(0, 8);
}

function docs_score_(r, catName, terms) {
  var title = r.title.toLowerCase(), kw = r.keywords.toLowerCase(), act = r.activityName.toLowerCase(),
      file = r.originalFileName.toLowerCase(), desc = r.description.toLowerCase(), cat = (catName || '').toLowerCase();
  var total = 0;
  for (var i = 0; i < terms.length; i++) {
    var t = terms[i], s = 0;
    if (title.indexOf(t) >= 0) s += 5;
    if ((' ' + title).indexOf(' ' + t) >= 0) s += 2;
    if (kw.indexOf(t) >= 0) s += 4;
    if (act.indexOf(t) >= 0) s += 3;
    if (file.indexOf(t) >= 0) s += 2;
    if (cat.indexOf(t) >= 0) s += 2;
    if (desc.indexOf(t) >= 0) s += 1;
    if (String(r.year) === t) s += 2;
    if (s === 0) return -1;      // semua kata harus cocok di salah satu kolom
    total += s;
  }
  return total;
}

var DOC_STATUSES_ = ['memproses', 'tersedia', 'gagal', 'hilang', 'dihapus'];

function docs_search_(token, p) {
  var user = auth_requireSession_(token);
  var terms = docs_terms_(docs_opt_(p.q));
  var catId = docs_opt_(p.categoryId); if (catId !== undefined) v_id_(catId, 'Kategori');
  var uploaderId = docs_opt_(p.uploaderId); if (uploaderId !== undefined) v_id_(uploaderId, 'Pengunggah');
  var year = docs_opt_(p.year); if (year !== undefined) year = v_year_(year);
  var fileType = docs_opt_(p.fileType);
  if (fileType !== undefined && ['pdf', 'docx', 'xlsx', 'pptx', 'jpg', 'png'].indexOf(fileType) < 0) throw userError_('DATA_TIDAK_VALID', 'Jenis file tidak valid.');
  var activity = docs_opt_(p.activity);
  if (activity !== undefined) activity = v_text_(activity, 'Kegiatan', { max: 100 }).toLowerCase();
  var sort = docs_opt_(p.sort) || (terms.length ? 'relevansi' : 'terbaru');
  if (['relevansi', 'terbaru'].indexOf(sort) < 0) throw userError_('DATA_TIDAK_VALID', 'Urutan tidak valid.');
  var page = docs_opt_(p.page) === undefined ? 1 : p.page, size = docs_opt_(p.pageSize) === undefined ? CFG.PAGE_SIZE_DEFAULT : p.pageSize;
  if (!Number.isInteger(page) || page < 1 || !Number.isInteger(size) || size < 1 || size > CFG.PAGE_SIZE_MAX) throw userError_('DATA_TIDAK_VALID', 'Halaman tidak valid.');
  var mine = p.mine === true, status = 'tersedia';
  if (!mine && docs_opt_(p.status) !== undefined && p.status !== 'tersedia') {
    auth_requireAdmin_(token);   // melihat status lain hanya untuk admin
    if (DOC_STATUSES_.indexOf(p.status) < 0) throw userError_('DATA_TIDAK_VALID', 'Status tidak valid.');
    status = p.status;
  }

  var maps = docs_maps_(), hits = [];
  db_readAll_('Documents').forEach(function (r) {
    if (mine) { if (r.uploadedBy !== user.userId || r.fileStatus === 'dihapus') return; }
    else if (r.fileStatus !== status) return;
    if (catId && r.categoryId !== catId) return;
    if (uploaderId && r.uploadedBy !== uploaderId) return;
    if (year !== undefined && Number(r.year) !== year) return;
    if (fileType && docs_ext_(r.originalFileName) !== fileType) return;
    if (activity && r.activityName.toLowerCase() !== activity) return;
    var score = terms.length ? docs_score_(r, maps.cats[r.categoryId], terms) : 0;
    if (score < 0) return;
    hits.push({ r: r, score: score });
  });
  hits.sort(function (a, b) {
    if (sort === 'relevansi' && b.score !== a.score) return b.score - a.score;
    return a.r.uploadedAt < b.r.uploadedAt ? 1 : (a.r.uploadedAt > b.r.uploadedAt ? -1 : 0);
  });
  var total = hits.length, from = (page - 1) * size;
  return { ok: true, total: total, page: page, pageSize: size, totalPages: Math.max(1, Math.ceil(total / size)),
    items: hits.slice(from, from + size).map(function (h) { return docs_public_(h.r, maps); }) };
}

// Daftar nilai untuk filter (tahun, kegiatan, pengunggah, jenis file) dari dokumen yang tersedia.
function docs_filters_(token, p) {
  auth_requireSession_(token);
  var maps = docs_maps_(), years = {}, acts = {}, ups = {}, types = {};
  db_readAll_('Documents').forEach(function (r) {
    if (r.fileStatus !== 'tersedia') return;
    years[r.year] = 1; if (r.activityName) acts[r.activityName] = 1; ups[r.uploadedBy] = 1; types[docs_ext_(r.originalFileName)] = 1;
  });
  return { ok: true,
    years: Object.keys(years).map(Number).sort(function (a, b) { return b - a; }),
    activities: Object.keys(acts).sort(function (a, b) { return a.toLowerCase() < b.toLowerCase() ? -1 : 1; }),
    uploaders: Object.keys(ups).map(function (id) { return { userId: id, name: maps.users[id] || '(akun tidak ditemukan)' }; }),
    fileTypes: Object.keys(types).sort() };
}

function docs_dashboard_(token, p) {
  var user = auth_requireSession_(token), maps = docs_maps_(), counts = {}, avail = [], mine = [];
  db_readAll_('Documents').forEach(function (r) {
    if (r.fileStatus === 'tersedia') { avail.push(r); counts[r.categoryId] = (counts[r.categoryId] || 0) + 1; }
    if (r.uploadedBy === user.userId && r.fileStatus !== 'dihapus') mine.push(r);
  });
  var byNew = function (a, b) { return a.uploadedAt < b.uploadedAt ? 1 : -1; };
  avail.sort(byNew); mine.sort(byNew);
  return { ok: true, totalAccessible: avail.length,
    categories: db_readAll_('Categories').filter(function (c) { return c.activeStatus === 'active'; })
      .map(function (c) { return { categoryId: c.categoryId, categoryName: c.categoryName, count: counts[c.categoryId] || 0 }; }),
    recent: avail.slice(0, 5).map(function (r) { return docs_public_(r, maps); }),
    mine: { count: mine.length, recent: mine.slice(0, 5).map(function (r) { return docs_public_(r, maps); }) } };
}

// ---------- Detail, buka, ubah, hapus ----------
function docs_row_(documentId) {
  var r = db_findBy_('Documents', 'documentId', v_id_(documentId, 'ID dokumen'));
  if (!r) throw userError_('TIDAK_DITEMUKAN', 'Dokumen tidak ditemukan.');
  return r;
}

function docs_get_(token, p) {
  var user = auth_requireSession_(token, { fresh: true }), r = docs_row_(p.documentId);
  var isAdmin = user.role === 'admin';
  if (r.fileStatus !== 'tersedia' && !isAdmin && !(r.uploadedBy === user.userId && r.fileStatus !== 'dihapus')) {
    throw userError_('TIDAK_DITEMUKAN', 'Dokumen tidak ditemukan.');
  }
  var out = { ok: true, document: docs_public_(r, docs_maps_()) };
  if (isAdmin) { out.admin = { driveFileId: r.driveFileId, contentHash: r.contentHash, requestId: r.requestId }; }
  return out;
}

// Membuka dokumen lewat backend: cek sesi + status, ambil dari Drive. Klien tidak pernah memegang ID Drive.
function docs_open_(token, p) {
  auth_requireSession_(token);
  var r = docs_row_(p.documentId);
  if (r.fileStatus !== 'tersedia') throw userError_('FILE_TIDAK_TERSEDIA', 'File belum atau tidak tersedia di arsip.');
  var f = ds_getVerifiedFile_(r.driveFileId);
  if (!f) {
    try { db_updateById_('Documents', r.documentId, { fileStatus: 'hilang', updatedAt: nowIso_() }); } catch (e) {}
    audit_('sistem', 'file_hilang', r.documentId, 'terdeteksi_saat_buka');
    throw userError_('FILE_HILANG', 'File tidak ditemukan di Drive (dipindahkan atau dihapus). Hubungi admin.');
  }
  if (f.getSize() > CFG.MAX_FILE_BYTES * 2) throw userError_('FILE_TERLALU_BESAR', 'File terlalu besar untuk dibuka lewat web. Hubungi admin.');
  return { ok: true, fileName: r.originalFileName, mimeType: r.mimeType, size: f.getSize(),
           base64: Utilities.base64Encode(f.getBlob().getBytes()) };
}

// Gambar mini otomatis untuk daftar dokumen (tanpa klik). Hanya setelah login; hasil di-cache agar hemat kuota Drive.
function docs_thumb_(token, p) {
  auth_requireSession_(token);
  var r = docs_row_(p.documentId);
  if (r.fileStatus !== 'tersedia') throw userError_('FILE_TIDAK_TERSEDIA', 'File belum atau tidak tersedia di arsip.');
  var cache = CacheService.getScriptCache(), key = 'thumb:' + r.documentId + ':' + hmacHex_('thumb:' + r.driveFileId).substring(0, 12);
  var hit = cache.get(key);
  if (hit) { var c = JSON.parse(hit); return c.n ? { ok: true, available: false } : { ok: true, available: true, mime: c.m, base64: c.b }; }
  var t = null;
  try { t = ds_thumbnail_(r.driveFileId); } catch (e) { console.error('thumbnail gagal: ' + (e && e.message)); }
  if (!t) { cache.put(key, JSON.stringify({ n: 1 }), 120); return { ok: true, available: false }; }   // coba lagi setelah 2 menit
  var json = JSON.stringify({ m: t.mime, b: t.base64 });
  if (json.length < 90000) cache.put(key, json, 6 * 60 * 60);   // batas nilai CacheService 100 KB
  return { ok: true, available: true, mime: t.mime, base64: t.base64 };
}

// Pengunggah dan admin dapat memperbaiki metadata.
function docs_updateMeta_(token, p) {
  var user = auth_requireSession_(token, { fresh: true }), r = docs_row_(p.documentId);
  if (user.role !== 'admin' && r.uploadedBy !== user.userId) throw userError_('DILARANG', 'Anda tidak berwenang mengubah dokumen ini.');
  if (r.fileStatus !== 'tersedia' && r.fileStatus !== 'hilang') throw userError_('STATUS_TIDAK_SESUAI', 'Dokumen ini tidak dapat diubah.');
  var meta = docs_validateMeta_(p, r.categoryId);
  db_mutate_('Documents', r.documentId, function (t) {
    if (t.fileStatus !== 'tersedia' && t.fileStatus !== 'hilang') throw userError_('STATUS_TIDAK_SESUAI', 'Dokumen ini tidak dapat diubah.');
    return meta;
  }, 'Dokumen tidak ditemukan.');
  audit_(user.userId, 'ubah_metadata', r.documentId, 'berhasil');
  return { ok: true, document: docs_public_(docs_row_(r.documentId), docs_maps_()) };
}

// Admin: tandai dihapus dan pindahkan file ke Sampah Drive (masih dapat dipulihkan dari Drive).
function docs_remove_(token, p) {
  var admin = auth_requireAdmin_(token), r = docs_row_(p.documentId);
  if (r.fileStatus === 'dihapus') throw userError_('STATUS_TIDAK_SESUAI', 'Dokumen sudah dihapus.');
  db_mutate_('Documents', r.documentId, function () { return { fileStatus: 'dihapus' }; }, 'Dokumen tidak ditemukan.');
  var trashed = false;
  try { trashed = ds_trash_(r.driveFileId); } catch (e) { console.error('trash gagal: ' + (e && e.message)); }
  audit_(admin.userId, 'hapus_dokumen', r.documentId, trashed ? 'berhasil' : 'baris_saja');
  return { ok: true, driveTrashed: trashed };
}

// ---------- Integritas (admin) ----------
function docs_integrityCheck_(token, p) {
  var admin = auth_requireAdmin_(token);
  var offset = docs_opt_(p.offset) === undefined ? 0 : p.offset, limit = docs_opt_(p.limit) === undefined ? 60 : p.limit;
  if (!Number.isInteger(offset) || offset < 0 || !Number.isInteger(limit) || limit < 1 || limit > 100) throw userError_('DATA_TIDAK_VALID', 'Parameter tidak valid.');
  var started = Date.now(), rows = db_readAll_('Documents').filter(function (r) { return r.fileStatus !== 'dihapus'; });
  var batch = rows.slice(offset, offset + limit), changes = [], sizeMismatch = [], checked = 0;
  for (var i = 0; i < batch.length; i++) {
    if (Date.now() - started > 4 * 60 * 1000) break;   // sisakan waktu; lanjutkan dengan offset berikutnya
    var r = batch[i]; checked++;
    var name = r.documentId + '__' + r.originalFileName;
    if (r.fileStatus === 'tersedia' || r.fileStatus === 'hilang') {
      var f = ds_getVerifiedFile_(r.driveFileId);
      if (!f && r.fileStatus === 'tersedia') { db_updateById_('Documents', r.documentId, { fileStatus: 'hilang', updatedAt: nowIso_() }); changes.push({ documentId: r.documentId, title: r.title, change: 'tersedia -> hilang' }); }
      else if (f && r.fileStatus === 'hilang') { db_updateById_('Documents', r.documentId, { fileStatus: 'tersedia', updatedAt: nowIso_() }); changes.push({ documentId: r.documentId, title: r.title, change: 'hilang -> tersedia' }); }
      if (f && Number(r.fileSize) !== f.getSize()) sizeMismatch.push({ documentId: r.documentId, title: r.title, recorded: Number(r.fileSize), actual: f.getSize() });
    } else if ((r.fileStatus === 'memproses' || r.fileStatus === 'gagal') && docs_age_(r.updatedAt) >= CFG.UPLOAD_STALE_MS) {
      var found = ds_findByName_(name, Number(r.fileSize));
      if (found) { db_updateById_('Documents', r.documentId, { driveFileId: found.getId(), fileStatus: 'tersedia', updatedAt: nowIso_() }); changes.push({ documentId: r.documentId, title: r.title, change: r.fileStatus + ' -> tersedia (dipulihkan)' }); }
      else if (r.fileStatus === 'memproses') { db_updateById_('Documents', r.documentId, { fileStatus: 'gagal', updatedAt: nowIso_() }); changes.push({ documentId: r.documentId, title: r.title, change: 'memproses -> gagal' }); }
    }
  }
  var next = offset + checked;
  audit_(admin.userId, 'cek_integritas', '', changes.length + ' perubahan');
  return { ok: true, checked: checked, total: rows.length, nextOffset: next < rows.length ? next : null, changes: changes, sizeMismatch: sizeMismatch };
}

// File di folder Drive yang tidak cocok dengan baris sheet mana pun. TIDAK menghapus apa pun.
function docs_findOrphans_(token, p) {
  var admin = auth_requireAdmin_(token), byId = {};
  db_readAll_('Documents').forEach(function (r) { byId[r.documentId] = r; });
  var it = ds_folder_().getFiles(), orphans = [], seen = 0, LIMIT = 1000;
  while (it.hasNext() && seen < LIMIT) {
    var f = it.next(); seen++;
    if (f.isTrashed()) continue;
    var m = /^([A-Z]{1,3}-[0-9a-f]{12})__/.exec(f.getName()), row = m ? byId[m[1]] : null;
    var known = row && row.driveFileId === f.getId() && row.fileStatus !== 'dihapus';
    if (!known) orphans.push({ name: f.getName(), size: f.getSize(), driveFileId: f.getId(),
      reason: !m ? 'nama tidak dikenal' : (!row ? 'tidak ada di sheet' : 'tidak cocok dengan baris sheet') });
  }
  audit_(admin.userId, 'cari_file_yatim', '', orphans.length + ' ditemukan');
  return { ok: true, scanned: seen, truncated: it.hasNext(), orphans: orphans };
}
