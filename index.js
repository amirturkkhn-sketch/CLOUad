// <!--GAMFC-->version base on commit 43fad05dcdae3b723c53c226f8181fc5bd47223e, time is 2023-06-22 15:20:02 UTC<!--GAMFC-END-->
import { connect } from 'cloudflare:sockets';

let userID = 'd342d11e-d424-4583-b36e-524ab1f0afa4'; 
let proxyIP = ''; 

export default {
	async fetch(request, env, ctx) {
		try {
			userID = env.UUID || userID;
			proxyIP = env.PROXYIP || proxyIP;
			
			const url = new URL(request.url);
			const path = url.pathname;
			const method = request.method;
			const host = url.host;
			const upgradeHeader = request.headers.get('Upgrade');

			// ۱. اگر اتصال پروکسی بود، هدایت به هسته VLESS (EdgeTunnel)
			if (upgradeHeader === 'websocket') {
				return await vlessOverWSHandler(request);
			}

			// بررسی وجود دیتابیس برای بخش پنل مدیریت
			if (!env.DB) {
				return new Response(generateErrorPage("خطا: دیتابیس D1 متصل نشده است."), {
					status: 500,
					headers: { "Content-Type": "text/html;charset=UTF-8" }
				});
			}

			// ۲. ساب متنی Base64
			if (path.startsWith("/sub/") && method === "GET") {
				const username = path.split("/")[2];
				const user = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
				if (!user) return new Response("User not found", { status: 404 });

				const link = `vless://${user.uuid}@${host}:443?encryption=none&security=tls&sni=${host}&fp=randomized&type=ws&host=${host}&path=%2F%3Fed%3D2048#${encodeURIComponent(user.username)}`;
				return new Response(btoa(unescape(encodeURIComponent(link))), {
					headers: { "Content-Type": "text/plain;charset=UTF-8", "Cache-Control": "no-store" }
				});
			}

			// ۳. ساب YAML برای کلش
			if (path.startsWith("/yaml/") && method === "GET") {
				const username = path.split("/")[2];
				const user = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
				if (!user) return new Response("User not found", { status: 404 });

				const yamlContent = `proxies:
  - name: "${user.username}-${user.protocol}"
    type: vless
    server: ${host}
    port: 443
    uuid: ${user.uuid}
    network: ws
    tls: true
    sni: ${host}
    skip-cert-verify: true
    client-fingerprint: chrome
    ws-opts:
      path: "/?ed=2048"
      headers:
        Host: ${host}`;

				return new Response(yamlContent, {
					headers: { "Content-Type": "text/yaml;charset=UTF-8", "Cache-Control": "no-store" }
				});
			}

			// ۴. API لیست کاربران
			if (path === "/api/users" && method === "GET") {
				const { results } = await env.DB.prepare("SELECT * FROM users ORDER BY created_at DESC").all();
				return jsonResponse({
					success: true,
					users: results,
					metrics: {
						total: results.length,
						active: results.filter(u => u.status === 'active').length,
					}
				});
			}

			// ۵. API ایجاد کاربر جدید
			if (path === "/api/users" && method === "POST") {
				const body = await request.json();
				let rawName = body.username ? body.username.trim() : "";
				if (!rawName) return jsonResponse({ error: "نام کاربری الزامی است." }, 400);

				const username = rawName.startsWith("KING_") ? rawName : "KING_" + rawName;
				const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first();
				if (existing) return jsonResponse({ error: "این نام کاربری قبلاً ثبت شده است." }, 400);

				const id = "usr_" + Date.now();
				const newUuid = generateUUID();

				await env.DB.prepare(
					`INSERT INTO users (id, username, uuid, protocol, traffic, expire, port, tls, adblock, adult_block, status) 
					 VALUES (?, ?, ?, 'VLESS', '100 GB', '30 روز', '443', 'TLS 1.3', 'on', 'on', 'active')`
				).bind(id, username, newUuid).run();

				return jsonResponse({ success: true, message: "کاربر با موفقیت ثبت شد." });
			}

			// ۶. API حذف کاربر
			if (path.startsWith("/api/users/") && method === "DELETE") {
				const id = path.split("/")[3];
				await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(id).run();
				return jsonResponse({ success: true });
			}

			// صفحه اصلی پنل مدیریتی شما
			return new Response(getMasterDashboardHtml(host), {
				headers: { "Content-Type": "text/html;charset=UTF-8" }
			});

		} catch (err) {
			return new Response(err.toString(), { status: 500 });
		}
	},
};

// --- توابع هسته EdgeTunnel برای پروکسی VLESS ---
async function vlessOverWSHandler(request) {
	const webSocketPair = new WebSocketPair();
	const [client, webSocket] = Object.values(webSocketPair);
	webSocket.accept();

	let address = '';
	let portWithRandomLog = '';
	const log = (info, event) => { console.log(`[${address}:${portWithRandomLog}] ${info}`, event || ''); };
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
	const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

	let remoteSocketWapper = { value: null };
	let udpStreamWrite = null;
	let isDns = false;

	readableWebSocketStream.pipeTo(new WritableStream({
		async write(chunk, controller) {
			if (isDns && udpStreamWrite) return udpStreamWrite(chunk);
			if (remoteSocketWapper.value) {
				const writer = remoteSocketWapper.value.writable.getWriter();
				await writer.write(chunk);
				writer.releaseLock();
				return;
			}
			const { hasError, message, portRemote = 443, addressRemote = '', rawDataIndex, vlessVersion = new Uint8Array([0, 0]), isUDP } = processVlessHeader(chunk, userID);
			address = addressRemote;
			portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp ' : 'tcp '} `;
			if (hasError) throw new Error(message);
			if (isUDP) {
				if (portRemote === 53) isDns = true;
				else throw new Error('UDP proxy only enable for DNS which is port 53');
			}
			const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
			const rawClientData = chunk.slice(rawDataIndex);
			if (isDns) {
				const { write } = await handleUDPOutBound(webSocket, vlessResponseHeader, log);
				udpStreamWrite = write;
				udpStreamWrite(rawClientData);
				return;
			}
			handleTCPOutBound(remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log);
		},
	})).catch((err) => { log('readableWebSocketStream pipeTo error', err); });

	return new Response(null, { status: 101, webSocket: client });
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log) {
	async function connectAndWrite(address, port) {
		const tcpSocket = connect({ hostname: address, port: port });
		remoteSocket.value = tcpSocket;
		log(`connected to ${address}:${port}`);
		const writer = tcpSocket.writable.getWriter();
		await writer.write(rawClientData);
		writer.releaseLock();
		return tcpSocket;
	}
	async function retry() {
		const tcpSocket = await connectAndWrite(proxyIP || addressRemote, portRemote);
		tcpSocket.closed.catch(() => {}).finally(() => { safeCloseWebSocket(webSocket); });
		remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);
	}
	const tcpSocket = await connectAndWrite(addressRemote, portRemote);
	remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry, log);
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
	let readableStreamCancel = false;
	return new ReadableStream({
		start(controller) {
			webSocketServer.addEventListener('message', (event) => {
				if (!readableStreamCancel) controller.enqueue(event.data);
			});
			webSocketServer.addEventListener('close', () => {
				safeCloseWebSocket(webSocketServer);
				if (!readableStreamCancel) controller.close();
			});
			webSocketServer.addEventListener('error', (err) => { controller.error(err); });
			const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
			if (error) controller.error(error);
			else if (earlyData) controller.enqueue(earlyData);
		},
		cancel(reason) {
			if (readableStreamCancel) return;
			readableStreamCancel = true;
			safeCloseWebSocket(webSocketServer);
		}
	});
}

function processVlessHeader(vlessBuffer, userID) {
	if (vlessBuffer.byteLength < 24) return { hasError: true, message: 'invalid data' };
	const version = new Uint8Array(vlessBuffer.slice(0, 1));
	let isValidUser = false;
	if (stringify(new Uint8Array(vlessBuffer.slice(1, 17))) === userID) isValidUser = true;
	if (!isValidUser) return { hasError: true, message: 'invalid user' };

	const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
	const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];
	let isUDP = false;
	if (command === 1) {} else if (command === 2) { isUDP = true; } else { return { hasError: true, message: 'command not support' }; }
	
	const portIndex = 18 + optLength + 1;
	const portRemote = new DataView(vlessBuffer.slice(portIndex, portIndex + 2)).getUint16(0);
	let addressIndex = portIndex + 2;
	const addressBuffer = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1));
	const addressType = addressBuffer[0];
	let addressLength = 0;
	let addressValueIndex = addressIndex + 1;
	let addressValue = '';

	switch (addressType) {
		case 1:
			addressLength = 4;
			addressValue = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
			break;
		case 2:
			addressLength = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
			addressValueIndex += 1;
			addressValue = new TextDecoder().decode(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
			break;
		case 3:
			addressLength = 16;
			const dataView = new DataView(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
			const ipv6 = [];
			for (let i = 0; i < 8; i++) ipv6.push(dataView.getUint16(i * 2).toString(16));
			addressValue = ipv6.join(':');
			break;
		default:
			return { hasError: true, message: 'invalid addressType' };
	}
	return { hasError: false, addressRemote: addressValue, addressType, portRemote, rawDataIndex: addressValueIndex + addressLength, vlessVersion: version, isUDP };
}

async function remoteSocketToWS(remoteSocket, webSocket, vlessResponseHeader, retry, log) {
	let vlessHeader = vlessResponseHeader;
	let hasIncomingData = false;
	await remoteSocket.readable.pipeTo(new WritableStream({
		async write(chunk, controller) {
			hasIncomingData = true;
			if (webSocket.readyState !== WS_READY_STATE_OPEN) controller.error('ws closed');
			if (vlessHeader) {
				webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
				vlessHeader = null;
			} else {
				webSocket.send(chunk);
			}
		},
	})).catch(() => { safeCloseWebSocket(webSocket); });
	if (hasIncomingData === false && retry) retry();
}

function base64ToArrayBuffer(base64Str) {
	if (!base64Str) return { error: null };
	try {
		base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
		const decode = atob(base64Str);
		return { earlyData: Uint8Array.from(decode, c => c.charCodeAt(0)).buffer, error: null };
	} catch (error) { return { error }; }
}

function isValidUUID(uuid) {
	return /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(uuid);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
function safeCloseWebSocket(socket) {
	try { if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) socket.close(); } catch (e) {}
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) byteToHex.push((i + 256).toString(16).slice(1));
function unsafeStringify(arr, offset = 0) {
	return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}
function stringify(arr, offset = 0) {
	const uuid = unsafeStringify(arr, offset);
	if (!isValidUUID(uuid)) throw TypeError("Invalid UUID");
	return uuid;
}

async function handleUDPOutBound(webSocket, vlessResponseHeader, log) {
	let isVlessHeaderSent = false;
	const transformStream = new TransformStream({
		transform(chunk, controller) {
			for (let index = 0; index < chunk.byteLength;) {
				const lengthBuffer = chunk.slice(index, index + 2);
				const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
				controller.enqueue(new Uint8Array(chunk.slice(index + 2, index + 2 + udpPakcetLength)));
				index = index + 2 + udpPakcetLength;
			}
		}
	});
	transformStream.readable.pipeTo(new WritableStream({
		async write(chunk) {
			const resp = await fetch('https://1.1.1.1/dns-query', { method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: chunk });
			const dnsQueryResult = await resp.arrayBuffer();
			const udpSize = dnsQueryResult.byteLength;
			const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
			if (webSocket.readyState === WS_READY_STATE_OPEN) {
				if (isVlessHeaderSent) webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
				else {
					webSocket.send(await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
					isVlessHeaderSent = true;
				}
			}
		}
	})).catch(() => {});
	const writer = transformStream.writable.getWriter();
	return { write(chunk) { writer.write(chunk); } };
}

function jsonResponse(data, status = 200) {
	return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json;charset=UTF-8" } });
}

function generateUUID() {
	return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
		var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
		return v.toString(16);
	});
}

function generateErrorPage(msg) {
	return `<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><title>خطا</title><style>body{background:#030508;color:#fff;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;}.box{background:#0a0e17;border:1px solid #ef4444;padding:30px;border-radius:14px;text-align:center;}h2{color:#ef4444;}</style></head><body><div class="box"><h2>خطا</h2><p>${msg}</p></div></body></html>`;
}

// قالب پنل مدیریتی زیبای شما
function getMasterDashboardHtml(host) {
	return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KING PANEL</title>
    <style>
        :root { --bg-base: #030508; --bg-card: #0a0e17; --border-color: #1e2634; --border-gold: rgba(245, 158, 11, 0.4); --gold: #f59e0b; --text-main: #f3f4f6; --text-muted: #9ca3af; --success: #10b981; --danger: #ef4444; --vless: #3b82f6; }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: system-ui, -apple-system, sans-serif; }
        body { background-color: var(--bg-base); color: var(--text-main); padding: 14px; min-height: 100vh; }
        .wrapper { max-width: 1400px; margin: 0 auto; }
        .header { display: flex; justify-content: space-between; align-items: center; background: var(--bg-card); border: 1px solid var(--border-color); padding: 16px 22px; border-radius: 16px; margin-bottom: 18px; }
        .logo-text { font-size: 22px; font-weight: 900; color: var(--gold); letter-spacing: 2px; }
        .server-status-pill { display: flex; align-items: center; gap: 8px; font-size: 12px; background: rgba(16, 185, 129, 0.12); color: var(--success); padding: 7px 14px; border-radius: 20px; border: 1px solid rgba(16, 185, 129, 0.3); font-weight: 700; }
        .pulse-dot { width: 8px; height: 8px; background: var(--success); border-radius: 50%; box-shadow: 0 0 10px var(--success); }
        .toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; background: var(--bg-card); border: 1px solid var(--border-color); padding: 14px 18px; border-radius: 14px; gap: 12px; flex-wrap: wrap; }
        .search-box { flex: 1; min-width: 250px; background: var(--bg-base); border: 1px solid var(--border-color); border-radius: 12px; padding: 11px 16px; color: white; outline: none; font-size: 13px; }
        .btn-gold { background: linear-gradient(135deg, #f59e0b, #d97706); color: #000; border: none; padding: 11px 22px; font-weight: 900; border-radius: 12px; cursor: pointer; font-size: 13px; }
        .users-list { display: flex; flex-direction: column; gap: 14px; }
        .user-card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 16px; padding: 18px; }
        .card-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; }
        .icon-btn { width: 34px; height: 34px; background: var(--bg-base); border: 1px solid var(--border-color); border-radius: 9px; display: flex; align-items: center; justify-content: center; cursor: pointer; color: var(--text-muted); font-size: 14px; }
        .icon-btn.del:hover { background: rgba(239, 68, 68, 0.2); color: var(--danger); border-color: var(--danger); }
        .badge-active { background: rgba(16, 185, 129, 0.15); color: var(--success); padding: 4px 10px; border-radius: 7px; font-size: 11px; font-weight: bold; }
        .username-title { font-size: 16px; font-weight: 900; color: white; }
        .card-bottom-btns { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 14px; }
        .sub-btn { background: var(--bg-base); border: 1px solid var(--border-color); color: var(--text-main); padding: 10px; border-radius: 10px; font-size: 12px; font-weight: bold; text-align: center; text-decoration: none; display: flex; align-items: center; justify-content: center; gap: 6px; }
        .sub-btn.purple { background: rgba(139, 92, 246, 0.1); color: #a78bfa; grid-column: span 2; }
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(3,5,8,0.88); justify-content: center; align-items: center; padding: 15px; z-index: 2000; }
        .modal-content { background: var(--bg-card); border: 1px solid var(--border-gold); width: 100%; max-width: 500px; padding: 28px; border-radius: 20px; }
        input { width: 100%; padding: 12px 16px; background: var(--bg-base); border: 1px solid var(--border-color); color: white; border-radius: 12px; outline: none; margin-top: 8px; margin-bottom: 16px; }
    </style>
</head>
<body>
    <div class="wrapper">
        <header class="header">
            <div class="logo-text">KING PANEL</div>
            <div class="server-status-pill"><div class="pulse-dot"></div><span>آنلاین و فعال</span></div>
        </header>
        <div class="toolbar">
            <input type="text" class="search-box" id="search-input" placeholder="🔍 جستجوی نام کاربری..." onkeyup="filterUsers()">
            <button class="btn-gold" onclick="openModal()">+ ایجاد کاربر جدید</button>
        </div>
        <div class="users-list" id="users-container"></div>
        <div class="modal" id="userModal">
            <div class="modal-content">
                <h3 style="color:var(--gold); margin-bottom:14px;">ایجاد کاربر جدید</h3>
                <form id="user-form">
                    <label style="font-size:12px; color:var(--text-muted);">نام کاربری (پیشوند KING_ اضافه می‌شود)</label>
                    <input type="text" id="f-username" required placeholder="مثال: omid">
                    <div style="display:flex; gap:10px;">
                        <button type="button" class="sub-btn" style="flex:1;" onclick="closeModal()">انصراف</button>
                        <button type="submit" class="btn-gold" style="flex:2;">ثبت کاربر</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    <script>
        let allUsersCache = [];
        const currentHost = "${host}";

        async function loadUsers() {
            try {
                const res = await fetch('/api/users');
                const data = await res.json();
                if(data.success) {
                    allUsersCache = data.users;
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
                const subUrl = \`https://\${currentHost}/sub/\${u.username}\`;
                const yamlUrl = \`https://\${currentHost}/yaml/\${u.username}\`;
                container.innerHTML += \`
                    <div class="user-card">
                        <div class="card-top">
                            <div class="icon-btn del" onclick="deleteUser('\${u.id}')" title="حذف">🗑️</div>
                            <div style="display:flex; align-items:center; gap:8px;">
                                <span class="badge-active">● فعال</span>
                                <span class="username-title">\${u.username}</span>
                            </div>
                        </div>
                        <div style="font-size:12px; color:var(--text-muted); font-family:monospace; word-break:break-all;">UUID: \${u.uuid}</div>
                        <div class="card-bottom-btns">
                            <a href="\${subUrl}" target="_blank" class="sub-btn">📄 ساب متنی</a>
                            <a href="\${yamlUrl}" target="_blank" class="sub-btn purple">⚡ ساب YAML (کلش)</a>
                        </div>
                    </div>
                \`;
            });
        }

        function filterUsers() {
            const query = document.getElementById('search-input').value.toLowerCase();
            renderUsers(allUsersCache.filter(u => u.username.toLowerCase().includes(query)));
        }

        function openModal() { document.getElementById('userModal').style.display = 'flex'; }
        function closeModal() { document.getElementById('userModal').style.display = 'none'; }

        document.getElementById('user-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const res = await fetch('/api/users', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: document.getElementById('f-username').value })
            });
            const data = await res.json();
            if(data.success) { closeModal(); loadUsers(); } else { alert(data.error); }
        });

        async function deleteUser(id) {
            if(!confirm('حذف شود؟')) return;
            const res = await fetch('/api/users/' + id, { method: 'DELETE' });
            if((await res.json()).success) loadUsers();
        }

        loadUsers();
    </script>
</body>
</html>`;
}
