/* ============================================================
   Iamx的资料库 - 配置文件
   只改这一个文件，就能调整站点、密钥和文案，无需动其他代码
   ============================================================ */
window.IAMX_CONFIG = {

  /* ---------- 站点 ---------- */
  siteName: 'Iamx的资料库',
  siteUrl: 'https://91rjy.infinityfreeapp.com',  // 目标站点（Discuz 论坛），验证通过后直接切换过去
  homePath: '/forum.php',      // 动态密码通道验证通过后的跳转目标（站点首页）

  /* ---------- 登录接口参数（Discuz member.php，一般无需修改） ---------- */
  loginParams: {
    mod: 'logging',
    action: 'login',
    loginsubmit: 'yes',
    loginfield: 'username',   // username = 用户名登录；email = 邮箱登录（页面可切换）
    questionid: '0',          // 安全提问，未设置则为 0
    answer: ''                // 安全提问答案
  },
  autoLoginCookie: '2592000', // 勾选“自动登录”时的 cookie 时长（秒，2592000 = 30 天）

  /* ---------- 动态密码（本地 TOTP，RFC 6238，无需联网） ---------- */
  totp: {
    secret: 'DA4GH5IGJAY52JIGTFTANYCITOP6XJS6', // 初始 Base32 密钥，可自行更换（A-Z、2-7）
    period: 60,                                  // 刷新周期（秒）
    digits: 6                                    // 动态密码位数
  },
  // 说明：点击“刷新二维码”会随机生成一个新密钥，二维码内容与倒计时一并重置

  /* ---------- 特殊字符限制 ---------- */
  // 目标网站的安全策略会拒绝包含这些字符的请求，此类用户名/密码无法自动登录
  forbiddenChars: '<>"\'()',

  /* ---------- 文案 ---------- */
  texts: {
    privateAppTip: '本应用为私密应用，请联系管理员新增账户登录'
  }
};
