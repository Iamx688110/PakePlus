/* ============================================================
   Iamx的资料库 - 应用逻辑
   依赖：qrcode.js（二维码库）、config.js（配置）
   纯前端运行，无需服务器、无需安装任何东西

   两条独立进入通道（任选其一即可）：
     通道一「账号密码」：填写用户名/密码 → 进入资料库
     通道二「动态密码」：扫码获得动态密码 → 输入 → 确认
   ============================================================ */

/* ---------- 修复二维码库默认只取字符低字节的问题：替换为正确的 UTF-8 编码 ---------- */
qrcode.stringToBytes = function (s) {
  var bytes = [];
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (c < 0x80) { bytes.push(c); }
    else if (c < 0x800) { bytes.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f)); }
    else if (c < 0xd800 || c >= 0xe000) { bytes.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f)); }
    else {
      i++;
      c = 0x10000 + (((c & 0x3ff) << 10) | (s.charCodeAt(i) & 0x3ff));
      bytes.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 0x3f), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    }
  }
  return bytes;
};

(function () {
  'use strict';

  var CFG = window.IAMX_CONFIG;
  var SITE = CFG.siteUrl.replace(/\/+$/, '');
  var LOGIN_PAGE = SITE + '/member.php?mod=logging&action=login';
  var HOME_PAGE = SITE + (CFG.homePath || '/forum.php');   // 动态密码通道的跳转目标
  var PERIOD = CFG.totp.period;
  var DIGITS = CFG.totp.digits;
  var SECRET = CFG.totp.secret;   // 当前密钥；点击“刷新二维码”会重新随机生成
  var FORBIDDEN = new RegExp('[' + CFG.forbiddenChars.replace(/[-\]\\^]/g, '\\$&') + ']');
  var PRIVATE_TIP = CFG.texts.privateAppTip;

  var $ = function (id) { return document.getElementById(id); };
  var loginMode = CFG.loginParams.loginfield === 'email' ? 'email' : 'username';
  var currentDyn = '';
  var currentWindow = 0;
  var epochOffset = 0;     // 刷新二维码时把计时整体前移到当下，倒计时归满重来
  var navigating = false;

  /* ==================== 纯 JS TOTP（RFC 6238 / HMAC-SHA1） ==================== */
  function sha1Bytes(bytes) {
    var ml = bytes.length;
    var m = bytes.slice();
    m.push(0x80);
    while (m.length % 64 !== 56) m.push(0);
    var bitLen = ml * 8;
    for (var i = 7; i >= 0; i--) m.push(Math.floor(bitLen / Math.pow(2, i * 8)) & 0xff);
    var h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
    var w = new Array(80);
    for (var b = 0; b < m.length; b += 64) {
      for (var j = 0; j < 16; j++) w[j] = (m[b + j * 4] << 24) | (m[b + j * 4 + 1] << 16) | (m[b + j * 4 + 2] << 8) | m[b + j * 4 + 3];
      for (var j2 = 16; j2 < 80; j2++) { var n = w[j2 - 3] ^ w[j2 - 8] ^ w[j2 - 14] ^ w[j2 - 16]; w[j2] = (n << 1) | (n >>> 31); }
      var a = h0, bb = h1, c = h2, d = h3, e = h4, f, k, t;
      for (var j3 = 0; j3 < 80; j3++) {
        if (j3 < 20) { f = (bb & c) | (~bb & d); k = 0x5A827999; }
        else if (j3 < 40) { f = bb ^ c ^ d; k = 0x6ED9EBA1; }
        else if (j3 < 60) { f = (bb & c) | (bb & d) | (c & d); k = 0x8F1BBCDC; }
        else { f = bb ^ c ^ d; k = 0xCA62C1D6; }
        t = (((a << 5) | (a >>> 27)) + f + e + k + w[j3]) | 0;
        e = d; d = c; c = (bb << 30) | (bb >>> 2); bb = a; a = t;
      }
      h0 = (h0 + a) | 0; h1 = (h1 + bb) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0; h4 = (h4 + e) | 0;
    }
    var out = [];
    [h0, h1, h2, h3, h4].forEach(function (h) { out.push((h >>> 24) & 0xff, (h >>> 16) & 0xff, (h >>> 8) & 0xff, h & 0xff); });
    return out;
  }
  function hmacSha1Bytes(key, msg) {
    var k = key.slice();
    if (k.length > 64) k = sha1Bytes(k);
    while (k.length < 64) k.push(0);
    var inner = sha1Bytes(k.map(function (x) { return x ^ 0x36; }).concat(msg));
    return sha1Bytes(k.map(function (x) { return x ^ 0x5c; }).concat(inner));
  }
  function base32Decode(str) {
    var alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', bits = 0, value = 0, out = [];
    for (var i = 0; i < str.length; i++) {
      var idx = alphabet.indexOf(str.charAt(i).toUpperCase());
      if (idx === -1) continue;
      value = (value << 5) | idx; bits += 5;
      if (bits >= 8) { bits -= 8; out.push((value >>> bits) & 0xff); }
    }
    return out;
  }
  function totpCode(secret, unixSeconds, digits) {
    var key = base32Decode(secret);
    var T = Math.floor(unixSeconds / PERIOD), msg = [];
    for (var i = 7; i >= 0; i--) msg.push(Math.floor(T / Math.pow(256, i)) & 0xff);
    var hs = hmacSha1Bytes(key, msg);
    var o = hs[19] & 0xf;
    var binary = ((hs[o] & 0x7f) << 24) | (hs[o + 1] << 16) | (hs[o + 2] << 8) | hs[o + 3];
    var mod = Math.pow(10, digits);
    return String(binary % mod).padStart(digits, '0');
  }
  /* 随机 Base32 密钥（优先使用加密安全随机源） */
  function randomSecret(length) {
    var alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    var buf = new Uint32Array(length);
    if (window.crypto && window.crypto.getRandomValues) {
      window.crypto.getRandomValues(buf);
    } else {
      for (var i = 0; i < length; i++) buf[i] = Math.floor(Math.random() * 4294967296);
    }
    var out = '';
    for (var j = 0; j < length; j++) out += alphabet[buf[j] % 32];
    return out;
  }

  /* ==================== toast / 状态栏 ==================== */
  var toastTimer = null;
  function toast(msg) {
    $('toastText').textContent = msg;
    var t = $('toast');
    t.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.classList.remove('show'); }, 3200);
  }

  function setStatus(type, head, body, actions) {
    var box = $('statusBox');
    var icons = {
      ok: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M20 6L9 17l-5-5"/></svg>',
      err: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M18 6L6 18M6 6l12 12"/></svg>',
      warn: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M12 2l9 17H3z"/><path d="M12 9v4"/><path d="M12 16.5v.5"/></svg>',
      info: '<span class="spinner"></span>'
    };
    var html = '<div class="head">' + (icons[type] || '') + '<span>' + head + '</span></div>';
    if (body) html += '<div>' + body + '</div>';
    if (actions && actions.length) {
      html += '<div class="actions">';
      actions.forEach(function (a) { html += '<button type="button" data-act="' + a.act + '"' + (a.primary ? ' class="primary"' : '') + '>' + a.label + '</button>'; });
      html += '</div>';
    }
    box.innerHTML = html;
    box.className = 'status show ' + type;
    if (actions) {
      box.querySelectorAll('.actions button').forEach(function (btn) {
        btn.addEventListener('click', function () {
          var act = btn.getAttribute('data-act');
          if (act === 'retry') { attemptAccountLogin(); }
          else if (act === 'copyopen') { copyText($('password').value).then(function () { openSiteLoginPage(); }); }
          else if (act === 'openlogin') { openSiteLoginPage(); }
        });
      });
    }
  }
  function hideStatus() { $('statusBox').className = 'status'; }

  /* ==================== 表单交互 ==================== */
  $('loginFieldSeg').querySelectorAll('button').forEach(function (btn) {
    btn.addEventListener('click', function () {
      $('loginFieldSeg').querySelectorAll('button').forEach(function (b) { b.classList.remove('active'); });
      btn.classList.add('active');
      loginMode = btn.getAttribute('data-field');
      $('username').placeholder = loginMode === 'email' ? '请输入邮箱' : '请输入用户名';
    });
  });

  $('eyeBtn').addEventListener('click', function () {
    var p = $('password');
    var show = p.type === 'password';
    p.type = show ? 'text' : 'password';
    $('eyeOpen').style.display = show ? 'none' : 'block';
    $('eyeClosed').style.display = show ? 'block' : 'none';
  });
  ['keydown', 'keyup'].forEach(function (ev) {
    $('password').addEventListener(ev, function (e) {
      var on = false;
      try { on = e.getModifierState && e.getModifierState('CapsLock'); } catch (err) {}
      $('capsHint').classList.toggle('show', !!on);
    });
  });
  $('password').addEventListener('blur', function () { $('capsHint').classList.remove('show'); });

  $('registerLink').addEventListener('click', function () {
    toast(PRIVATE_TIP);
    $('vaultPanel').classList.remove('shake');
    void $('vaultPanel').offsetWidth;
    $('vaultPanel').classList.add('shake');
  });

  /* ---------- 记住用户名 / 偏好 ---------- */
  try {
    var savedUser = localStorage.getItem('iamx_user');
    if (savedUser) $('username').value = savedUser;
    var savedMode = localStorage.getItem('iamx_loginmode');
    if (savedMode === 'email') {
      var segBtn = document.querySelector('#loginFieldSeg button[data-field="email"]');
      if (segBtn) segBtn.click();
    }
    var savedAuto = localStorage.getItem('iamx_autologin');
    if (savedAuto === '1') $('autoLogin').checked = true;
  } catch (e) {}

  /* ==================== 动态密码（TOTP）+ 二维码 ==================== */
  var ringCirc = 2 * Math.PI * 19;

  /* 当前周期信息：code = 当前动态密码，remain = 距下次更换的秒数 */
  function tick() {
    var t = Math.floor(Date.now() / 1000) - epochOffset;
    return {
      code: totpCode(SECRET, t, DIGITS),
      win: Math.floor(t / PERIOD),
      remain: PERIOD - (t % PERIOD)
    };
  }

  function refreshDyn(flash) {
    var now = tick();
    if (now.win !== currentWindow || now.code !== currentDyn) {
      currentWindow = now.win;
      currentDyn = now.code;
      drawQR(CFG.siteName + '动态密码 ' + now.code);
      if (flash) flashQR();
    }
    $('ringNum').textContent = now.remain;
    $('ringProg').style.strokeDashoffset = String(ringCirc * (1 - now.remain / PERIOD));
    $('ringProg').style.stroke = now.remain <= 5 ? '#dc2626' : '#d97706';
  }
  function flashQR() {
    var f = $('qrFrame');
    f.classList.add('flash');
    setTimeout(function () { f.classList.remove('flash'); }, 260);
  }
  function drawQR(text) {
    try {
      var qr = qrcode(0, 'M');
      qr.addData(text);
      qr.make();
      var n = qr.getModuleCount(), quiet = 3, cell = 8;
      var size = (n + quiet * 2) * cell;
      var canvas = $('qrCanvas');
      canvas.width = size; canvas.height = size;
      canvas.style.width = '196px'; canvas.style.height = '196px';
      var ctx = canvas.getContext('2d');
      ctx.fillStyle = '#ffffff';
      ctx.fillRect(0, 0, size, size);
      ctx.fillStyle = '#111827';
      for (var r = 0; r < n; r++) {
        for (var c = 0; c < n; c++) {
          if (qr.isDark(r, c)) ctx.fillRect((c + quiet) * cell, (r + quiet) * cell, cell, cell);
        }
      }
    } catch (e) {}
  }
  setInterval(function () { refreshDyn(true); }, 1000);
  $('secretText').textContent = SECRET;
  refreshDyn(false);

  /* ---------- 刷新二维码：重新随机生成密钥，二维码内容与倒计时一并重置 ---------- */
  $('refreshQrBtn').addEventListener('click', function () {
    SECRET = randomSecret(32);
    epochOffset = Math.floor(Date.now() / 1000);
    currentWindow = -1;          // 强制重画二维码
    currentDyn = '';
    $('secretText').textContent = SECRET;
    $('dynCodeInput').value = '';
    setCodeMsg('', '');
    refreshDyn(true);
    toast('二维码已刷新，请重新扫码');
  });

  /* ---------- 动态密码输入框 ---------- */
  var codeInput = $('dynCodeInput');
  function setCodeMsg(text, type) {
    var m = $('codeMsg');
    m.textContent = text || '';
    m.className = 'code-msg' + (type ? ' ' + type : '');
  }
  function shakeCodeRow() {
    var row = $('codeRow');
    row.classList.remove('shake');
    void row.offsetWidth;
    row.classList.add('shake');
  }
  codeInput.addEventListener('input', function () {
    var v = codeInput.value.replace(/\D/g, '');
    if (v !== codeInput.value) codeInput.value = v;
    if ($('codeMsg').classList.contains('err')) setCodeMsg('', '');
  });
  /* 输入框内回车 → 通道二（动态密码） */
  codeInput.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') { e.preventDefault(); attemptCodeLogin(); }
  });

  /* ==================== 剪贴板（仅用于特殊字符密码的降级方案） ==================== */
  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).then(function () { return true; }).catch(function () { return legacyCopy(text); });
    }
    return Promise.resolve(legacyCopy(text));
  }
  function legacyCopy(text) {
    try {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.cssText = 'position:fixed;opacity:0;pointer-events:none';
      document.body.appendChild(ta);
      ta.select();
      var ok = document.execCommand('copy');
      document.body.removeChild(ta);
      return ok;
    } catch (e) { return false; }
  }

  /* ==================== 通道一：账号密码登录 ==================== */
  function buildLoginUrl() {
    var params = new URLSearchParams();
    var base = CFG.loginParams;
    params.set('mod', base.mod);
    params.set('action', base.action);
    params.set('loginsubmit', base.loginsubmit);
    params.set('loginfield', loginMode);
    params.set('username', $('username').value.trim());
    params.set('password', $('password').value);
    params.set('questionid', base.questionid);
    params.set('answer', base.answer);
    if ($('autoLogin').checked) params.set('cookietime', CFG.autoLoginCookie);
    return SITE + '/member.php?' + params.toString();
  }

  /* 直接在当前标签页切换到网站（不弹窗、不关闭任何窗口） */
  function openSiteLoginPage() {
    window.location.replace(LOGIN_PAGE);
  }

  /* 「进入资料库」：只走账号通道，不需要动态密码 */
  function attemptAccountLogin() {
    if (navigating) return;
    hideStatus();
    var user = $('username').value.trim();
    var pass = $('password').value;

    if (!user) { setStatus('err', '请输入' + (loginMode === 'email' ? '邮箱' : '用户名'), ''); $('username').focus(); return; }
    if (!pass) { setStatus('err', '请输入密码', ''); $('password').focus(); return; }

    if (FORBIDDEN.test(user) || FORBIDDEN.test(pass)) {
      setStatus('warn', '无法自动登录：凭证包含特殊字符',
        '网站安全策略会拒绝包含 <b>' + escapeHtml(CFG.forbiddenChars) + '</b> 的请求，此类用户名/密码无法自动提交。可复制密码后打开网站登录页，手动粘贴登录。', [
        { act: 'copyopen', label: '复制密码并打开登录页', primary: true },
        { act: 'openlogin', label: '仅打开登录页' }
      ]);
      return;
    }

    try {
      if ($('rememberMe').checked) {
        localStorage.setItem('iamx_user', user);
        localStorage.setItem('iamx_loginmode', loginMode);
      } else {
        localStorage.removeItem('iamx_user');
      }
      localStorage.setItem('iamx_autologin', $('autoLogin').checked ? '1' : '0');
    } catch (err) {}

    go(buildLoginUrl(), true);
  }

  /* ==================== 通道二：动态密码登录 ==================== */
  /* 「确认」：只走动态密码通道，不需要账号密码 */
  function attemptCodeLogin() {
    if (navigating) return;
    hideStatus();
    var code = codeInput.value.trim();

    if (!code) {
      setCodeMsg('请先扫描二维码并输入动态密码', 'err');
      shakeCodeRow();
      codeInput.focus();
      return;
    }

    /* 动态密码校验：当前周期或上一个周期均视为有效（兼容临界更换） */
    var now = tick();
    var prev = totpCode(SECRET, Math.floor(Date.now() / 1000) - epochOffset - PERIOD, DIGITS);
    if (code !== now.code && code !== prev) {
      setCodeMsg('动态密码验证失败，请保存本页 ID 并发送给管理员', 'err');
      shakeCodeRow();
      codeInput.value = '';
      codeInput.focus();
      return;
    }

    setCodeMsg('验证通过，正在进入资料库…', 'ok');
    go(HOME_PAGE, false);
  }

  /* ==================== 统一跳转 ==================== */
  /* 验证通过后：提示 → 禁用按钮 → 同标签页直接切换到目标页面（不弹窗、不关闭窗口） */
  function go(url, viaStatus) {
    if (navigating) return;
    navigating = true;
    if (viaStatus) {
      setStatus('info', '正在进入资料库…', '验证通过，正在切换到目标站点');
    }
    $('submitBtn').disabled = true;
    $('confirmBtn').disabled = true;
    setTimeout(function () { window.location.replace(url); }, 350);
  }

  function escapeHtml(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  /* ==================== 事件绑定 ==================== */
  /* 表单提交 / 输入框内回车 → 通道一（账号密码） */
  $('loginForm').addEventListener('submit', function (e) {
    e.preventDefault();
    attemptAccountLogin();
  });
  /* 「进入资料库」按钮点击 → 通道一（按钮保留 type=submit+form 属性以支持输入框内回车提交；
     点击与提交可能先后触发同一逻辑，由 navigating 守卫去重，无副作用） */
  $('submitBtn').addEventListener('click', function () {
    attemptAccountLogin();
  });
  /* 「确认」按钮 → 通道二（动态密码） */
  $('confirmBtn').addEventListener('click', attemptCodeLogin);
})();
