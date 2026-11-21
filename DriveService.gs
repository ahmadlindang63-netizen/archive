/**
 * DriveService.gs — semua operasi Google Drive. Model A: folder arsip TIDAK dibagikan publik.
 * Browser tidak pernah mengirim ID file Drive; hanya documentId (ID sheet). ID Drive dibaca server dari sheet.
 */
function ds_folder_() { return DriveApp.getFolderById(cfgGet_('FOLDER_ID')); }

function ds_isPublic_(access) {
  return access === DriveApp.Access.ANYONE || access === DriveApp.Access.ANYONE_WITH_LINK;
}

// Mencari file hasil upload sebelumnya (nama deterministik) untuk pemulihan tanpa membuat file ganda.
function ds_findByName_(name, size) {
  var it = ds_folder_().getFilesByName(name);
  while (it.hasNext()) {
    var f = it.next();
    if (!f.isTrashed() && f.getSize() === size) return f;
  }
  return null;
}

// Membuat file di folder arsip. Menolak jika folder/file terbuka publik.
function ds_create_(bytes, mime, name, documentId) {
  var folder = ds_folder_();
  if (ds_isPublic_(folder.getSharingAccess())) {
    throw userError_('FOLDER_TIDAK_AMAN', 'Folder arsip terbuka untuk publik. Hubungi admin untuk memperbaiki pengaturan berbagi folder.');
  }
  var file = folder.createFile(Utilities.newBlob(bytes, mime, name));
  file.setDescription('osis-archive:' + documentId);
  if (ds_isPublic_(file.getSharingAccess())) {
    file.setTrashed(true);   // file yang baru kita buat sendiri; jangan dibiarkan publik
    throw userError_('FOLDER_TIDAK_AMAN', 'File baru terbuka untuk publik, sehingga dibatalkan. Hubungi admin.');
  }
  if (file.getSize() !== bytes.length) {
    file.setTrashed(true);
    throw new Error('Ukuran file di Drive tidak sama dengan yang dikirim.');
  }
  return file.getId();
}

// Mengembalikan file hanya jika masih ada, tidak di tempat sampah, dan berada di folder arsip.
function ds_getVerifiedFile_(driveFileId) {
  if (!driveFileId) return null;
  var f;
  try { f = DriveApp.getFileById(driveFileId); } catch (e) { return null; }
  if (f.isTrashed()) return null;
  var parents = f.getParents(), folderId = cfgGet_('FOLDER_ID');
  while (parents.hasNext()) if (parents.next().getId() === folderId) return f;
  return null;
}

function ds_trash_(driveFileId) {
  var f = ds_getVerifiedFile_(driveFileId);
  if (!f) return false;
  f.setTrashed(true);   // masih dapat dipulihkan dari Sampah Drive
  return true;
}

// Gambar mini (halaman pertama / pratinjau kecil) dari Drive. Mengembalikan null jika belum ada atau tidak tersedia.
// File Office/PDF baru diunggah kadang belum punya gambar mini; hasil null tidak berarti galat.
var THUMB_MAX_BYTES_ = 300000;
function ds_thumbnail_(driveFileId) {
  var f = ds_getVerifiedFile_(driveFileId);
  if (!f) return null;
  var blob = null;
  try { blob = f.getThumbnail(); } catch (e) { return null; }
  if (!blob) return null;
  var bytes = blob.getBytes(), mime = blob.getContentType();
  if (!bytes || !bytes.length || bytes.length > THUMB_MAX_BYTES_) return null;
  if (mime !== 'image/png' && mime !== 'image/jpeg') return null;
  return { mime: mime, base64: Utilities.base64Encode(bytes) };
}
