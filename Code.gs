/**
 * Code.gs — satu-satunya pintu masuk dari browser: api(action, token, payload).
 * Semua fungsi lain berakhiran "_" sehingga tidak dapat dipanggil langsung dari browser.
 * Setiap rute memeriksa sesi/peran sendiri di backend. Payload TIDAK PERNAH dicatat ke log.
 * Bagian berikutnya menambah rute dokumen dan doGet().
 */
var ROUTES_ = {
  // Autentikasi
  'auth.salt':           function (t, p) { return auth_getSalt_(p.username); },
  'auth.login':          function (t, p) { return auth_login_(p); },
  'auth.activate':       function (t, p) { return auth_activate_(p); },
  'auth.logout':         function (t, p) { return auth_logout_(t, p); },
  'auth.resume':         function (t, p) { return auth_resume_(p); },               // publik: token perangkat -> sesi
  'auth.devices':        function (t, p) { return auth_devices_(t, p); },
  'auth.revokeDevices':  function (t, p) { return auth_revokeDevices_(t, p); },
  'auth.changePassword': function (t, p) { return auth_changePassword_(t, p); },
  'auth.me':             function (t, p) { return { ok: true, user: auth_requireSession_(t, { fresh: true }) }; },
  // Akun (admin, kecuali updateSelf)
  'users.list':          function (t, p) { return users_list_(t, p); },
  'users.create':        function (t, p) { return users_create_(t, p); },
  'users.setEnabled':    function (t, p) { return users_setEnabled_(t, p); },
  'users.setRole':       function (t, p) { return users_setRole_(t, p); },
  'users.resetPassword': function (t, p) { return users_resetPassword_(t, p); },
  'users.updateName':    function (t, p) { return users_updateName_(t, p); },
  'users.updateSelf':    function (t, p) { return users_updateSelf_(t, p); },
  // Kategori (list: semua anggota; lainnya: admin)
  'categories.list':      function (t, p) { return categories_list_(t, p); },
  'categories.create':    function (t, p) { return categories_create_(t, p); },
  'categories.update':    function (t, p) { return categories_update_(t, p); },
  'categories.setActive': function (t, p) { return categories_setActive_(t, p); },
  // Dokumen (semua anggota, kecuali yang ditandai admin)
  'docs.upload':         function (t, p) { return docs_upload_(t, p); },
  'docs.search':         function (t, p) { return docs_search_(t, p); },
  'docs.filters':        function (t, p) { return docs_filters_(t, p); },
  'docs.dashboard':      function (t, p) { return docs_dashboard_(t, p); },
  'docs.get':            function (t, p) { return docs_get_(t, p); },
  'docs.open':           function (t, p) { return docs_open_(t, p); },
  'docs.thumb':          function (t, p) { return docs_thumb_(t, p); },           // gambar mini otomatis
  'docs.updateMeta':     function (t, p) { return docs_updateMeta_(t, p); },       // pengunggah atau admin
  'docs.remove':         function (t, p) { return docs_remove_(t, p); },           // admin
  'docs.integrityCheck': function (t, p) { return docs_integrityCheck_(t, p); },   // admin
  'docs.findOrphans':    function (t, p) { return docs_findOrphans_(t, p); },      // admin
  // Aktivitas (admin)
  'audit.list':          function (t, p) { return audit_list_(t, p); }
};

// Halaman web. Tidak memuat rahasia: semua data lewat api() setelah login.
function doGet(e) {
  return HtmlService.createTemplateFromFile('Index').evaluate()
    .setTitle(CFG.APP_NAME)
    .addMetaTag('viewport', 'width=device-width, initial-scale=1');
}

function include_(name) { return HtmlService.createHtmlOutputFromFile(name).getContent(); }

function api(action, token, payload) {
  try {
    var route = Object.prototype.hasOwnProperty.call(ROUTES_, action) ? ROUTES_[action] : null;
    if (!route) return { ok: false, code: 'AKSI_TIDAK_DIKENAL', message: 'Permintaan tidak valid.' };
    if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) payload = {};
    var out = route(token, payload);
    return (out && typeof out.ok === 'boolean') ? out : { ok: true, data: out };
  } catch (e) {
    if (e && (e.isAuth || e.isUser)) return { ok: false, code: e.code, message: e.message };
    console.error('api galat [' + action + ']: ' + (e && e.message));
    return { ok: false, code: 'GALAT_SERVER', message: 'Terjadi kesalahan. Silakan coba lagi.' };
  }
}
