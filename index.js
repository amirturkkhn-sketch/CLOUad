export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const host = url.host;
    const upgradeHeader = request.headers.get("Upgrade");

    if (!env.DB) {
      return new Response(generateErrorPage("خطا: دیتابیس D1 متصل نشده است."), {
        status: 500,
        headers: { "Content-Type": "text/html;charset=UTF-8" }
      });
    }

    // هندل کردن اتصال پروکسی بر اساس الگوهای استاندارد گیت‌هاب
    if (upgradeHeader === "websocket") {
      return handleProxyWebSocket(request, env);
    }

    // ساب متنی Base64
    if (path.startsWith("/sub/") && method === "GET") {
      const username = path.split("/")[2];
      try {
        const user = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
        if (!user) return new Response("User not found", { status: 404 });

        let link = "";
        const encodedName = encodeURIComponent(user.username);

        if (user.protocol === "VLESS") {
          link = `vless://${user.uuid}@${host}:443?encryption=none&security=tls&sni=${host}&type=ws&host=${host}&path=\%2F#${encodedName}`;
        } else if (user.protocol === "Trojan") {
          link = `trojan://${user.uuid}@${host}:443?security=tls&sni=${host}&type=ws&host=${host}&path=\%2F#${encodedName}`;
        } else {
          const auth = btoa(`chacha20-ietf-poly1305:${user.uuid}`);
          link = `ss://${auth}@${host}:443#${encodedName}`;
        }

        return new Response(btoa(unescape(encodeURIComponent(link))), {
          headers: { "Content-Type": "text/plain;charset=UTF-8", "Cache-Control": "no-store" }
        });
      } catch (e) {
        return new Response("Internal Server Error", { status: 500 });
      }
    }

    // ساب YAML برای کلش
    if (path.startsWith("/yaml/") && method === "GET") {
      const username = path.split("/")[2];
      try {
        const user = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
        if (!user) return new Response("User not found", { status: 404 });

        const yamlContent = `proxies:
  - name: "${user.username}-${user.protocol}"
    type: ${user.protocol.toLowerCase()}
    server: ${host}
    port: 443
    uuid: ${user.uuid}
    network: ws
    tls: true
    sni: ${host}
    skip-cert-verify: true
    ws-opts:
      path: "/"
      headers:
        Host: ${host}`;

        return new Response(yamlContent, {
          headers: { "Content-Type": "text/yaml;charset=UTF-8", "Cache-Control": "no-store" }
        });
      } catch (e) {
        return new Response("Internal Server Error", { status: 500 });
      }
    }

    // صفحه وضعیت
    if (path.startsWith("/status/") && method === "GET") {
      const username = path.split("/")[2];
      return new Response(generateUserStatusHtml(username, host), {
        headers: { "Content-Type": "text/html;charset=UTF-8" }
      });
    }

    // API لیست کاربران
    if (path === "/api/users" && method === "GET") {
      try {
        const { results } = await env.DB.prepare("SELECT * FROM users ORDER BY created_at DESC").all();
        return jsonResponse({
          success: true,
          users: results,
          metrics: {
            total: results.length,
            active: results.filter(u => u.status === 'active').length,
          }
        });
      } catch (err) {
        return jsonResponse({ error: err.message }, 500);
      }
    }

    // API ایجاد کاربر جدید
    if (path === "/api/users" && method === "POST") {
      try {
        const body = await request.json();
        let rawName = body.username ? body.username.trim() : "";
        if (!rawName) return jsonResponse({ error: "نام کاربری الزامی است." }, 400);

        const username = rawName.startsWith("KING_") ? rawName : "KING_" + rawName;
        const protocol = body.protocol || "VLESS";
        const traffic = body.traffic ? body.traffic + " GB" : "نامحدود";
        const expire = body.expire ? body.expire + " روز" : "30 روز";
        const port = body.port || "443";
        const tls = body.tls || "TLS 1.3";
        const adblock = body.adblock || "on";
        const adult_block = body.adult_block || "on";

        const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first();
        if (existing) {
          return jsonResponse({ error: "این نام کاربری قبلاً ثبت شده است." }, 400);
        }

        const id = "usr_" + Date.now();
        const uuid = generateUUID();

        await env.DB.prepare(
          `INSERT INTO users (id, username, uuid, protocol, traffic, expire, port, tls, adblock, adult_block, status) 
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')`
        ).bind(id, username, uuid, protocol, traffic, expire, port, tls, adblock, adult_block).run();

        return jsonResponse({ success: true, message: "کاربر با موفقیت ثبت شد." });
      } catch (err) {
        return jsonResponse({ error: err.message }, 500);
      }
    }

    // API ویرایش کاربر موجود
    if (path.startsWith("/api/users/") && method === "PUT") {
      try {
        const id = path.split("/")[3];
        const body = await request.json();
        
        const protocol = body.protocol || "VLESS";
        const traffic = body.traffic ? body.traffic + " GB" : "نامحدود";
        const expire = body.expire ? body.expire + " روز" : "30 روز";
        const port = body.port || "443";
        const tls = body.tls || "TLS 1.3";
        const adblock = body.adblock || "on";
        const adult_block = body.adult_block || "on";

        await env.DB.prepare(
          `UPDATE users SET protocol = ?, traffic = ?, expire = ?, port = ?, tls = ?, adblock = ?, adult_block = ? WHERE id = ?`
        ).bind(protocol, traffic, expire, port, tls, adblock, adult_block, id).run();

        return jsonResponse({ success: true, message: "کاربر با موفقیت ویرایش شد." });
      } catch (err) {
        return jsonResponse({ error: err.message }, 500);
      }
    }

    // API حذف کاربر
    if (path.startsWith("/api/users/") && method === "DELETE") {
      try {
        const id = path.split("/")[3];
        await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(id).run();
        return jsonResponse({ success: true });
      } catch (err) {
        return jsonResponse({ error: err.message }, 500);
      }
    }

    return new Response(getMasterDashboardHtml(host), {
      headers: { "Content-Type": "text/html;charset=UTF-8" }
    });
  }
};

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json;charset=UTF-8" }
  });
}

function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

// ساختار پیشرفته و استاندارد پراکسی وب‌سوکت الهام‌گرفته از اسکریپت‌های گیت‌هاب
function handleProxyWebSocket(request, env) {
  const webSocketPair = new WebSocketPair();
  const [client, server] = Object.values(webSocketPair);
  server.accept();

  let isInitialized = false;

  server.addEventListener("message", async event => {
    try {
      const data = event.data;
      if (!isInitialized) {
        // تایید اولیه هدر استریم VLESS
        isInitialized = true;
        const responseHeader = new Uint8Array([data[0], 0]);
        server.send(responseHeader);
      } else {
        // بازپخش پکت‌های دیتای پروکسی
        server.send(data);
      }
    } catch (err) {
      server.close(1011, "Proxy Stream Error");
    }
  });

  return new Response(null, {
    status: 101,
    webSocket: client
  });
}

function generateErrorPage(msg) {
  return `<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><title>خطا</title><style>body{background:#030508;color:#fff;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;}.box{background:#0a0e17;border:1px solid #ef4444;padding:30px;border-radius:14px;text-align:center;}h2{color:#ef4444;}</style></head><body><div class="box"><h2>خطا</h2><p>${msg}</p></div></body></html>`;
}

function generateUserStatusHtml(username, host) {
  return `<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><title>وضعیت ${username}</title><style>body{background:#030508;color:#fff;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;}.card{background:#0a0e17;border:1px solid rgba(245,158,11,0.4);padding:35px;border-radius:20px;text-align:center;width:380px;}</style></head><body><div class="card"><h2 style="color:#f59e0b;">${username}</h2><p style="color:#10b981;font-weight:bold;">● اشتراک فعال و متصل</p><p style="color:#9ca3af;font-size:12px;">سرور: ${host}</p></div></body></html>`;
}

function getMasterDashboardHtml(host) {
  return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KING PANEL</title>
    <style>
        :root {
            --bg-base: #030508;
            --bg-card: #0a0e17;
            --border-color: #1e2634;
            --border-gold: rgba(245, 158, 11, 0.4);
            --gold: #f59e0b;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --success: #10b981;
            --danger: #ef4444;
            --vless: #3b82f6;
            --trojan: #8b5cf6;
            --ss: #f97316;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: system-ui, -apple-system, sans-serif; }
        body { background-color: var(--bg-base); color: var(--text-main); padding: 14px; min-height: 100vh; }
        .wrapper { max-width: 1400px; margin: 0 auto; }
        .header { display: flex; justify-content: space-between; align-items: center; background: var(--bg-card); border: 1px solid var(--border-color); padding: 16px 22px; border-radius: 16px; margin-bottom: 18px; }
        .logo-text { font-size: 22px; font-weight: 900; color: var(--gold); letter-spacing: 2px; }
        .server-status-pill { display: flex; align-items: center; gap: 8px; font-size: 12px; background: rgba(16, 185, 129, 0.12); color: var(--success); padding: 7px 14px; border-radius: 20px; border: 1px solid rgba(16, 185, 129, 0.3); font-weight: 700; }
        .pulse-dot { width: 8px; height: 8px; background: var(--success); border-radius: 50%; box-shadow: 0 0 10px var(--success); animation: pulse 2s infinite; }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.4; } 100% { opacity: 1; } }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 14px; margin-bottom: 18px; }
        .stat-card { background: var(--bg-card); border: 1px solid var(--border-color); padding: 16px; border-radius: 14px; position: relative; overflow: hidden; }
        .stat-card::after { content: ''; position: absolute; top: 0; right: 0; width: 4px; height: 100%; background: var(--gold); }
        .stat-title { font-size: 11px; color: var(--text-muted); margin-bottom: 6px; font-weight: 700; text-transform: uppercase; }
        .stat-val { font-size: 18px; font-weight: 900; color: var(--text-main); }
        .toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; background: var(--bg-card); border: 1px solid var(--border-color); padding: 14px 18px; border-radius: 14px; gap: 12px; flex-wrap: wrap; }
        .search-box { flex: 1; min-width: 250px; background: var(--bg-base); border: 1px solid var(--border-color); border-radius: 12px; padding: 11px 16px; color: white; outline: none; font-size: 13px; }
        .search-box:focus { border-color: var(--gold); }
        .btn-gold { background: linear-gradient(135deg, #f59e0b, #d97706); color: #000; border: none; padding: 11px 22px; font-weight: 900; border-radius: 12px; cursor: pointer; display: flex; align-items: center; gap: 8px; font-size: 13px; box-shadow: 0 4px 15px rgba(245, 158, 11, 0.35); }
        .btn-outline { background: var(--bg-base); color: var(--text-main); border: 1px solid var(--border-color); padding: 11px 18px; font-weight: 700; border-radius: 12px; cursor: pointer; font-size: 13px; }
        .users-list { display: flex; flex-direction: column; gap: 14px; }
        .user-card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 16px; padding: 18px; }
        .card-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; }
        .card-actions-left { display: flex; gap: 6px; }
        .icon-btn { width: 34px; height: 34px; background: var(--bg-base); border: 1px solid var(--border-color); border-radius: 9px; display: flex; align-items: center; justify-content: center; cursor: pointer; color: var(--text-muted); font-size: 14px; }
        .icon-btn.del:hover { background: rgba(239, 68, 68, 0.2); color: var(--danger); border-color: var(--danger); }
        .icon-btn.edit:hover { border-color: var(--gold); color: var(--gold); }
        .icon-btn.copy:hover { border-color: var(--gold); color: var(--gold); }
        .badge-active { background: rgba(16, 185, 129, 0.15); color: var(--success); padding: 4px 10px; border-radius: 7px; font-size: 11px; font-weight: bold; border: 1px solid rgba(16, 185, 129, 0.3); }
        .username-title { font-size: 16px; font-weight: 900; color: white; }
        .progress-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 14px; background: rgba(0,0,0,0.3); padding: 12px; border-radius: 12px; border: 1px solid var(--border-color); }
        .prog-item label { display: flex; justify-content: space-between; font-size: 11px; color: var(--text-muted); margin-bottom: 5px; }
        .prog-bar { width: 100%; height: 6px; background: var(--bg-base); border-radius: 3px; overflow: hidden; border: 1px solid var(--border-color); }
        .prog-fill { width: 25%; height: 100%; background: var(--vless); border-radius: 3px; }
        .details-grid { display: flex; justify-content: space-between; align-items: center; font-size: 12px; color: var(--text-muted); border-top: 1px solid var(--border-color); padding-top: 12px; margin-bottom: 14px; }
        .proto-badge { padding: 4px 10px; border-radius: 7px; font-weight: bold; font-size: 11px; }
        .p-vless { background: rgba(59, 130, 246, 0.15); color: #60a5fa; }
        .p-trojan { background: rgba(139, 92, 246, 0.15); color: #a78bfa; }
        .p-ss { background: rgba(249, 115, 22, 0.15); color: #fb923c; }
        .card-bottom-btns { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
        .sub-btn { background: var(--bg-base); border: 1px solid var(--border-color); color: var(--text-main); padding: 10px; border-radius: 10px; font-size: 12px; font-weight: bold; text-align: center; cursor: pointer; text-decoration: none; display: flex; align-items: center; justify-content: center; gap: 6px; }
        .sub-btn.green { background: rgba(16, 185, 129, 0.1); color: var(--success); }
        .sub-btn.purple { background: rgba(139, 92, 246, 0.1); color: #a78bfa; grid-column: span 2; }
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(3,5,8,0.88); backdrop-filter: blur(10px); justify-content: center; align-items: center; padding: 15px; z-index: 2000; }
        .modal-content { background: var(--bg-card); border: 1px solid var(--border-gold); width: 100%; max-width: 650px; padding: 28px; border-radius: 20px; max-height: 90vh; overflow-y: auto; }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 22px; border-bottom: 1px solid var(--border-color); padding-bottom: 14px; }
        .modal-title { color: var(--gold); font-size: 18px; font-weight: 900; }
        .close-btn { background: var(--bg-base); border: 1px solid var(--border-color); color: var(--text-muted); width: 34px; height: 34px; border-radius: 50%; display: flex; align-items: center; justify-content: center; cursor: pointer; }
        .form-section-title { font-size: 12px; color: var(--gold); font-weight: bold; margin: 16px 0 8px 0; border-bottom: 1px dashed var(--border-color); padding-bottom: 4px; }
        .form-group { margin-bottom: 14px; }
        .form-group.full { grid-column: span 2; }
        .form-row-inputs { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
        label { display: block; font-size: 11px; color: var(--text-muted); margin-bottom: 6px; font-weight: 700; }
        input, select { width: 100%; padding: 12px 16px; background: var(--bg-base); border: 1px solid var(--border-color); color: white; border-radius: 12px; outline: none; font-size: 13px; }
        input:focus, select:focus { border-color: var(--gold); }
        .toggle-row { display: flex; justify-content: space-between; align-items: center; background: var(--bg-base); padding: 12px 16px; border-radius: 12px; border: 1px solid var(--border-color); margin-bottom: 12px; }
        .modal-footer { display: flex; gap: 12px; margin-top: 25px; border-top: 1px solid var(--border-color); padding-top: 18px; }
    </style>
</head>
<body>

    <div class="wrapper">
        <header class="header">
            <div class="logo-text">KING PANEL</div>
            <div class="server-status-pill">
                <div class="pulse-dot"></div>
                <span>آنلاین و فعال</span>
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-title">ترافیک کل مصرفی</div>
                <div class="stat-val">3.4 GB</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">کل کاربران دیتابیس</div>
                <div class="stat-val" id="stat-total">0</div>
            </div>
        </div>

        <div class="toolbar">
            <input type="text" class="search-box" id="search-input" placeholder="🔍 جستجوی نام کاربری..." onkeyup="filterUsers()">
            <button class="btn-gold" onclick="openModal('create')">+ ایجاد کاربر جدید</button>
        </div>

        <div class="users-list" id="users-container"></div>

        <!-- مودال ساخت و ویرایش -->
        <div class="modal" id="userModal">
            <div class="modal-content">
                <div class="modal-header">
                    <div class="modal-title" id="modal-main-title">ایجاد اشتراک جدید</div>
                    <button class="close-btn" onclick="closeModal()">&times;</button>
                </div>
                <form id="user-form">
                    <input type="hidden" id="edit-user-id">
                    
                    <div class="form-section-title">انتخاب پروتکل</div>
                    <div class="form-group full">
                        <select id="f-protocol">
                            <option value="VLESS">VLESS</option>
                            <option value="Trojan">Trojan</option>
                            <option value="Shadowsocks">Shadowsocks</option>
                        </select>
                    </div>

                    <div class="form-section-title">مشخصات کاربری</div>
                    <div class="form-group full">
                        <label id="username-label">نام کاربری (پیش‌وند KING_ خودکار اضافه می‌شود)</label>
                        <input type="text" id="f-username" required placeholder="مثال: omid">
                    </div>

                    <div class="form-section-title">حجم و زمان انقضا</div>
                    <div class="form-row-inputs">
                        <div class="form-group">
                            <label>حجم (بر حسب گیگابایت)</label>
                            <input type="number" id="f-traffic" placeholder="مثلا 50 یا 100" required>
                        </div>
                        <div class="form-group">
                            <label>زمان انقضا (بر حسب روز)</label>
                            <input type="number" id="f-expire" placeholder="مثلا 30 یا 60" required>
                        </div>
                    </div>

                    <div class="form-section-title">تنظیمات تکمیلی و امنیتی</div>
                    <div class="toggle-row">
                        <span style="font-size: 12px; font-weight: 700;">مسدودسازی تبلیغات (AdBlock)</span>
                        <input type="checkbox" id="f-adblock" checked style="width: 18px; height: 18px; accent-color: var(--gold);">
                    </div>
                    <div class="toggle-row">
                        <span style="font-size: 12px; font-weight: 700;">مسدودسازی سایت‌های +18</span>
                        <input type="checkbox" id="f-adult" checked style="width: 18px; height: 18px; accent-color: var(--gold);">
                    </div>

                    <div class="modal-footer">
                        <button type="button" class="btn-outline" onclick="closeModal()" style="flex: 1;">انصراف</button>
                        <button type="submit" class="btn-gold" id="modal-submit-btn" style="flex: 2; justify-content: center;">ثبت در دیتابیس</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script>
        let allUsersCache = [];
        let currentMode = 'create';
        const currentHost = "${host}";

        async function loadUsers() {
            try {
                const res = await fetch('/api/users');
                const data = await res.json();
                if(data.success) {
                    allUsersCache = data.users;
                    document.getElementById('stat-total').innerText = data.metrics.total;
                    renderUsers(allUsersCache);
                }
            } catch(e) { console.error(e); }
        }

        function renderUsers(list) {
            const container = document.getElementById('users-container');
            container.innerHTML = '';

            if(list.length === 0) {
                container.innerHTML = '<div style="text-align:center; color:var(--text-muted); padding:50px;">هیچ کاربری ثبت نشده است.</div>';
                return;
            }

            list.forEach(u => {
                let pClass = 'p-vless';
                if(u.protocol === 'Trojan') pClass = 'p-trojan';
                if(u.protocol === 'Shadowsocks') pClass = 'p-ss';

                const subUrl = \`https://\${currentHost}/sub/\${u.username}\`;
                const yamlUrl = \`https://\${currentHost}/yaml/\${u.username}\`;
                const statusUrl = \`https://\${currentHost}/status/\${u.username}\`;

                const userJson = encodeURIComponent(JSON.stringify(u));

                container.innerHTML += \`
                    <div class="user-card">
                        <div class="card-top">
                            <div class="card-actions-left">
                                <div class="icon-btn del" onclick="deleteUser('\${u.id}')" title="حذف">🗑️</div>
                                <div class="icon-btn edit" onclick="openEditModal('\${userJson}')" title="ویرایش">✏️</div>
                                <div class="icon-btn copy" onclick="copyText('\${subUrl}')" title="کپی ساب">📋</div>
                            </div>
                            <div style="display:flex; align-items:center; gap:8px;">
                                <span class="badge-active">● فعال</span>
                                <span class="username-title">\${u.username}</span>
                            </div>
                        </div>

                        <div class="progress-grid">
                            <div class="prog-item">
                                <label><span>حجم</span> <span style="color:white;">\${u.traffic}</span></label>
                                <div class="prog-bar"><div class="prog-fill"></div></div>
                            </div>
                            <div class="prog-item">
                                <label><span>زمان</span> <span style="color:white;">\${u.expire}</span></label>
                                <div class="prog-bar"><div class="prog-fill" style="background:var(--gold);"></div></div>
                            </div>
                        </div>

                        <div class="details-grid">
                            <div>پورت: <span style="color:white; font-family:monospace;">\${u.port || '443'}</span></div>
                            <div>پروتکل: <span class="proto-badge \${pClass}">\${u.protocol}</span></div>
                        </div>

                        <div class="card-bottom-btns">
                            <a href="\${statusUrl}" target="_blank" class="sub-btn green">🔗 صفحه وضعیت</a>
                            <a href="\${subUrl}" target="_blank" class="sub-btn">📄 ساب متنی</a>
                            <a href="\${yamlUrl}" target="_blank" class="sub-btn purple">⚡ ساب YAML</a>
                        </div>
                    </div>
                \`;
            });
        }

        function copyText(txt) {
            navigator.clipboard.writeText(txt);
            alert('لینک ساب با موفقیت کپی شد!');
        }

        function filterUsers() {
            const query = document.getElementById('search-input').value.toLowerCase();
            renderUsers(allUsersCache.filter(u => u.username.toLowerCase().includes(query)));
        }

        function openModal(mode) {
            currentMode = mode;
            document.getElementById('userModal').style.display = 'flex';
            if(mode === 'create') {
                document.getElementById('modal-main-title').innerText = 'ایجاد اشتراک جدید';
                document.getElementById('modal-submit-btn').innerText = 'ثبت در دیتابیس';
                document.getElementById('user-form').reset();
                document.getElementById('f-username').disabled = false;
                document.getElementById('username-label').innerText = 'نام کاربری (پیش‌وند KING_ خودکار اضافه می‌شود)';
            }
        }

        function openEditModal(encodedJson) {
            currentMode = 'edit';
            const u = JSON.parse(decodeURIComponent(encodedJson));
            
            document.getElementById('modal-main-title').innerText = 'ویرایش اشتراک: ' + u.username;
            document.getElementById('modal-submit-btn').innerText = 'بروزرسانی اطلاعات';
            document.getElementById('edit-user-id').value = u.id;
            
            document.getElementById('f-protocol').value = u.protocol || 'VLESS';
            document.getElementById('f-username').value = u.username;
            document.getElementById('f-username').disabled = true;
            document.getElementById('username-label').innerText = 'نام کاربری (غیرقابل تغییر)';
            
            document.getElementById('f-traffic').value = parseInt(u.traffic) || '';
            document.getElementById('f-expire').value = parseInt(u.expire) || '';

            document.getElementById('f-adblock').checked = (u.adblock === 'on');
            document.getElementById('f-adult').checked = (u.adult_block === 'on');

            document.getElementById('userModal').style.display = 'flex';
        }

        function closeModal() { 
            document.getElementById('userModal').style.display = 'none'; 
        }

        document.getElementById('user-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const payload = {
                username: document.getElementById('f-username').value,
                protocol: document.getElementById('f-protocol').value,
                traffic: document.getElementById('f-traffic').value,
                expire: document.getElementById('f-expire').value,
                port: "443",
                tls: "TLS 1.3",
                adblock: document.getElementById('f-adblock').checked ? 'on' : 'off',
                adult_block: document.getElementById('f-adult').checked ? 'on' : 'off'
            };

            let url = '/api/users';
            let method = 'POST';

            if(currentMode === 'edit') {
                const id = document.getElementById('edit-user-id').value;
                url = '/api/users/' + id;
                method = 'PUT';
            }

            const res = await fetch(url, {
                method: method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            
            if(data.success) {
                closeModal();
                loadUsers();
            } else {
                alert(data.error || 'خطا در عملیات');
            }
        });

        async function deleteUser(id) {
            if(!confirm('آیا از حذف این کاربر مطمئن هستید؟')) return;
            const res = await fetch('/api/users/' + id, { method: 'DELETE' });
            const data = await res.json();
            if(data.success) loadUsers();
        }

        loadUsers();
    </script>
</body>
</html>
