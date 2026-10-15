export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Database initialization check
    if (!env.DB) {
      return new Response("Error: D1 Database (DB) binding is not configured in Cloudflare Workers settings.", {
        status: 500,
        headers: { 'Content-Type': 'text/plain;charset=UTF-8' }
      });
    }

    // Initialize tables if they don't exist
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE,
        uuid TEXT,
        protocol TEXT,
        traffic TEXT,
        expire TEXT,
        port TEXT,
        tls TEXT,
        adblock TEXT,
        adult_block TEXT,
        status TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `).run().catch(() => {});

    // API Endpoint: Create User & Generate Config Link
    if (url.pathname === '/api/create' && request.method === 'POST') {
      try {
        const data = await request.json();
        const rawUsername = data.username ? data.username.trim() : '';
        const username = 'KING_' + rawUsername.replace(/^KING_/, '');
        const id = 'user_' + Math.random().toString(36).substring(2, 9);
        const uuid = crypto.randomUUID();
        const port = Math.floor(Math.random() * (65535 - 1024) + 1024);
        const protocol = data.protocol || 'VLESS';
        const traffic = data.traffic || '50GB';
        const expire = data.expire || '30 Days';
        const tls = data.tls || 'TLS';
        const adblock = data.adblock ? '1' : '0';
        const adult_block = data.adult_block ? '1' : '0';

        await env.DB.prepare(
          `INSERT INTO users (id, username, uuid, protocol, traffic, expire, port, tls, adblock, adult_block, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(id, username, uuid, protocol, traffic, expire, port.toString(), tls, adblock, adult_block, 'active').run();

        const host = url.host;
        let subLink = '';
        if (protocol === 'VLESS') {
          subLink = `vless://${uuid}@${host}:${port}?encryption=none&security=${tls.toLowerCase()}&type=ws&host=${host}&path=%2F#${username}`;
        } else if (protocol === 'Trojan') {
          subLink = `trojan://${uuid}@${host}:${port}?security=${tls.toLowerCase()}&type=ws&host=${host}&path=%2F#${username}`;
        } else {
          subLink = `ss://${btoa('aes-256-gcm:' + uuid)}@${host}:${port}#${username}`;
        }

        return new Response(JSON.stringify({ success: true, link: subLink, port, uuid }), {
          headers: { 'Content-Type': 'application/json' }
        });
      } catch (err) {
        return new Response(JSON.stringify({ success: false, error: err.message }), {
          headers: { 'Content-Type': 'application/json' },
          status: 400
        });
      }
    }

    // API Endpoint: Get All Users List
    if (url.pathname === '/api/users' && request.method === 'GET') {
      try {
        const { results } = await env.DB.prepare(`SELECT * FROM users ORDER BY created_at DESC`).all();
        return new Response(JSON.stringify({ success: true, users: results }), {
          headers: { 'Content-Type': 'application/json' }
        });
      } catch (err) {
        return new Response(JSON.stringify({ success: false, error: err.message }), {
          headers: { 'Content-Type': 'application/json' },
          status: 400
        });
      }
    }

    // API Endpoint: Delete User
    if (url.pathname.startsWith('/api/delete/') && request.method === 'DELETE') {
      try {
        const id = url.pathname.split('/').pop();
        await env.DB.prepare(`DELETE FROM users WHERE id = ?`).bind(id).run();
        return new Response(JSON.stringify({ success: true }), {
          headers: { 'Content-Type': 'application/json' }
        });
      } catch (err) {
        return new Response(JSON.stringify({ success: false, error: err.message }), {
          headers: { 'Content-Type': 'application/json' },
          status: 400
        });
      }
    }

    // Luxury Black-and-Gold Frontend Management Panel UI
    const html = `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KING PANEL | پنل مدیریت پیشرفته وی پی ان</title>
    <style>
        :root {
            --bg-color: #080808;
            --card-bg: #121212;
            --gold: #d4af37;
            --gold-light: #f3e5ab;
            --gold-dark: #aa8c2c;
            --text-main: #f5f5f5;
            --text-muted: #999999;
            --border-gold: rgba(212, 175, 55, 0.3);
            --danger: #ff4d4d;
            --success: #2ecc71;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: Tahoma, sans-serif; }
        body {
            background-color: var(--bg-color);
            color: var(--text-main);
            min-height: 100vh;
            padding: 20px;
            display: flex;
            justify-content: center;
            align-items: flex-start;
        }
        .wrapper {
            width: 100%;
            max-width: 800px;
            display: flex;
            flex-direction: column;
            gap: 20px;
        }
        .container {
            background: var(--card-bg);
            border: 2px solid var(--gold);
            border-radius: 16px;
            padding: 30px;
            box-shadow: 0 0 30px rgba(212, 175, 55, 0.15);
        }
        header {
            text-align: center;
            margin-bottom: 25px;
        }
        h1 {
            color: var(--gold);
            font-size: 28px;
            letter-spacing: 2px;
            text-shadow: 0 0 12px rgba(212, 175, 55, 0.4);
            margin-bottom: 5px;
        }
        p.subtitle {
            color: var(--text-muted);
            font-size: 13px;
        }
        .form-group {
            margin-bottom: 18px;
        }
        label {
            display: block;
            color: var(--gold-light);
            font-size: 13px;
            margin-bottom: 8px;
        }
        input[type="text"], select {
            width: 100%;
            padding: 12px 15px;
            background: #1a1a1a;
            border: 1px solid var(--border-gold);
            border-radius: 8px;
            color: var(--text-main);
            font-size: 14px;
            outline: none;
            transition: 0.3s;
        }
        input[type="text"]:focus, select:focus {
            border-color: var(--gold);
            box-shadow: 0 0 10px rgba(212, 175, 55, 0.3);
        }
        .row {
            display: flex;
            gap: 15px;
        }
        .row .form-group {
            flex: 1;
        }
        .toggles {
            display: flex;
            justify-content: space-between;
            background: #1a1a1a;
            padding: 14px 18px;
            border-radius: 8px;
            border: 1px solid var(--border-gold);
            margin-bottom: 20px;
        }
        .toggle-item {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 13px;
            color: var(--gold-light);
            cursor: pointer;
        }
        .toggle-item input {
            accent-color: var(--gold);
            width: 18px;
            height: 18px;
        }
        .btn-submit {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, var(--gold), var(--gold-dark));
            color: #000;
            font-weight: bold;
            font-size: 16px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: 0.3s;
            box-shadow: 0 4px 15px rgba(212, 175, 55, 0.3);
        }
        .btn-submit:hover {
            opacity: 0.9;
            transform: translateY(-2px);
        }
        #resultBox {
            margin-top: 20px;
            background: #1a1a1a;
            border: 1px dashed var(--gold);
            padding: 15px;
            border-radius: 8px;
            display: none;
            word-break: break-all;
            font-size: 13px;
            color: var(--gold-light);
        }
        .users-section {
            margin-top: 10px;
        }
        h2.section-title {
            color: var(--gold);
            font-size: 18px;
            margin-bottom: 15px;
            border-bottom: 1px solid var(--border-gold);
            padding-bottom: 8px;
        }
        .user-card {
            background: #161616;
            border: 1px solid var(--border-gold);
            border-radius: 8px;
            padding: 12px 15px;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .user-info div {
            font-size: 13px;
            margin-bottom: 3px;
        }
        .user-name { color: var(--gold-light); font-weight: bold; font-size: 15px; }
        .user-details { color: var(--text-muted); }
        .btn-delete {
            background: var(--danger);
            color: white;
            border: none;
            padding: 8px 12px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 12px;
            transition: 0.2s;
        }
        .btn-delete:hover { opacity: 0.8; }
    </style>
</head>
<body>
    <div class="wrapper">
        <div class="container">
            <header>
                <h1>KING PANEL</h1>
                <p class="subtitle">سیستم مدیریت حرفه‌ای و لوکس اتصالات پرسرعت</p>
            </header>

            <form id="vpnForm">
                <div class="form-group">
                    <label>نام کاربری (پیشوند KING_ به صورت خودکار اعمال می‌شود)</label>
                    <input type="text" id="username" placeholder="مثلا ali یا admin" required>
                </div>

                <div class="form-group">
                    <label>پروتکل اتصال</label>
                    <select id="protocol">
                        <option value="VLESS">VLESS (WS / TLS)</option>
                        <option value="Trojan">Trojan</option>
                        <option value="Shadowsocks">Shadowsocks</option>
                    </select>
                </div>

                <div class="row">
                    <div class="form-group">
                        <label>حجم ترافیک</label>
                        <select id="traffic">
                            <option value="20GB">۲۰ گیگابایت</option>
                            <option value="50GB" selected>۵۰ گیگابایت</option>
                            <option value="100GB">۱۰۰ گیگابایت</option>
                            <option value="Unlimited">نامحدود</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>مدت زمان انقضا</label>
                        <select id="expire">
                            <option value="15 Days">۱۵ روزه</option>
                            <option value="30 Days" selected>۳۰ روزه</option>
                            <option value="60 Days">۶۰ روزه</option>
                            <option value="Unlimited">دائمی</option>
                        </select>
                    </div>
                </div>

                <div class="toggles">
                    <label class="toggle-item">
                        <input type="checkbox" id="adblock" checked> مسدودسازی تبلیغات
                    </label>
                    <label class="toggle-item">
                        <input type="checkbox" id="adult_block" checked> مسدودسازی محتوای بزرگسالان
                    </label>
                </div>

                <button type="submit" class="btn-submit">ساخت کانفیگ جدید</button>
            </form>

            <div id="resultBox"></div>
        </div>

        <div class="container users-section">
            <h2 class="section-title">لیست کاربران ثبت‌شده</h2>
            <div id="usersList">در حال بارگذاری لیست...</div>
        </div>
    </div>

    <script>
        async function loadUsers() {
            try {
                const res = await fetch('/api/users');
                const data = await res.json();
                const listEl = document.getElementById('usersList');
                if(data.success && data.users.length > 0) {
                    listEl.innerHTML = data.users.map(u => \`
                        <div class="user-card">
                            <div class="user-info">
                                <div class="user-name">\${u.username} (\${u.protocol})</div>
                                <div class="user-details">حجم: \${u.traffic} | انقضا: \${u.expire} | پورت: \${u.port}</div>
                            </div>
                            <button class="btn-delete" onclick="deleteUser('\${u.id}')">حذف</button>
                        </div>
                    \`).join('');
                } else {
                    listEl.innerHTML = '<div style="color: var(--text-muted); text-align: center; font-size: 13px;">هیچ کاربری هنوز ثبت نشده است.</div>';
                }
            } catch(e) {
                document.getElementById('usersList').innerHTML = '<div style="color: var(--danger); text-align: center;">خطا در دریافت لیست کاربران</div>';
            }
        }

        async function deleteUser(id) {
            if(!confirm('آیا از حذف این کاربر اطمینان دارید؟')) return;
            try {
                const res = await fetch('/api/delete/' + id, { method: 'DELETE' });
                const data = await res.json();
                if(data.success) {
                    loadUsers();
                } else {
                    alert('خطا در حذف کاربر');
                }
            } catch(e) {
                alert('خطا در ارتباط با سرور');
            }
        }

        document.getElementById('vpnForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value.trim();
            const protocol = document.getElementById('protocol').value;
            const traffic = document.getElementById('traffic').value;
            const expire = document.getElementById('expire').value;
            const adblock = document.getElementById('adblock').checked;
            const adult_block = document.getElementById('adult_block').checked;

            const resBox = document.getElementById('resultBox');
            resBox.style.display = 'block';
            resBox.innerHTML = 'در حال ساخت و ذخیره‌سازی کانفیگ در دیتابیس...';

            try {
                const response = await fetch('/api/create', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, protocol, traffic, expire, adblock, adult_block })
                });
                const data = await response.json();
                if(data.success) {
                    resBox.innerHTML = '<strong>لینک اتصال ساخته شد:</strong><br><br><input type="text" value="' + data.link + '" readonly style="width:100%; padding:8px; background:#111; color:#d4af37; border:1px solid #d4af37; border-radius:4px;" onclick="this.select()">';
                    loadUsers();
                } else {
                    resBox.innerHTML = 'خطا: ' + (data.error || 'ثبت انجام نشد');
                }
            } catch (err) {
                resBox.innerHTML = 'خطا در ارتباط با سرور';
            }
        });

        loadUsers();
    </script>
</body>
</html>`;

    return new Response(html, {
      headers: { 'Content-Type': 'text/html;charset=UTF-8' }
    });
  }
};
