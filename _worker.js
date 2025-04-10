// 部署完成后在网址后面加上这个，获取自建节点和机场聚合节点，/?token=auto或/auto或

/**
 * @description 管理员访问令牌。
 * 用于验证管理员身份，访问管理页面或获取完整订阅。
 * 可以在 Cloudflare 环境变量中设置 `TOKEN` 来覆盖。
 * @type {string}
 */
let adminToken = 'auto';

/**
 * @description 访客访问令牌。
 * 用于提供只读的订阅访问权限，无法访问管理页面。
 * 可以是任意字符串或 UUID。
 * 可以在 Cloudflare 环境变量中设置 `GUESTTOKEN` 或 `GUEST` 来覆盖。
 * @type {string}
 */
let guestToken = '';

/**
 * @description 输出的订阅文件名。
 * 当客户端需要下载文件时 (如 Clash 客户端)，指定下载的文件名。
 * 可以在 Cloudflare 环境变量中设置 `SUBNAME` 来覆盖。
 * @type {string}
 */
let subscriptionFileName = 'HC-CF-Workers-SUB';

/**
 * @description 客户端获取订阅的更新间隔（单位：小时）。
 * 会包含在响应头 `Profile-Update-Interval` 中，提示客户端多久更新一次订阅。
 * 可以在 Cloudflare 环境变量中设置 `SUBUPTIME` 来覆盖。
 * @type {number}
 */
let subscriptionUpdateIntervalHours = 6;

/**
 * @description 模拟的总流量（单位：TB）。
 * 用于生成 `Subscription-Userinfo` 响应头中的 `total` 值。
 * @type {number}
 */
let totalDataTB = 99;

/**
 * @description 模拟的过期时间戳（毫秒）。
 * 用于生成 `Subscription-Userinfo` 响应头中的 `expire` 值。
 * 默认为 2099-12-31。
 * @type {number}
 */
let expireTimestamp = 4102329600000;

/**
 * @description 默认的节点和订阅链接来源。
 * 这是一个多行字符串，每行包含一个节点链接（如 vmess://, trojan://）或一个订阅链接（http/https）。
 * 会与 KV 或环境变量中的来源合并。
 * @type {string}
 */
let defaultSources = `
https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray
https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt
https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt
https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2
https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/airport_sub_merge.txt
https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/sub_merge.txt
https://raw.githubusercontent.com/Pawdroid/Free-servers/refs/heads/main/sub
`;

/**
 * @description 订阅转换后端 API 的主机名。
 * 用于将合并后的节点列表转换为特定客户端格式 (Clash, Surge 等)。
 * 支持 `psub` 或兼容 `subconverter` API 的后端。
 * 可以在 Cloudflare 环境变量中设置 `SUBAPI` 来覆盖。
 * 例如: "api.v1.mk" 或 "sub.example.com"
 * @type {string}
 */
let subConverterApiHost = "psub.888005.xyz"; // 或 "subconverter.example.com"

/**
 * @description 订阅转换时使用的配置文件 URL。
 * 这个配置文件定义了转换规则、筛选、重命名等。
 * 可以在 Cloudflare 环境变量中设置 `SUBCONFIG` 来覆盖。
 * @type {string}
 */
let subConverterConfigUrl = "https://raw.githubusercontent.com/lee99/clash-ruler/refs/heads/main/Clash-LIAN.ini";

/**
 * @description 访问订阅转换后端使用的协议。
 * 根据 `subConverterApiHost` 是否包含 `http://` 自动判断，默认为 'https'。
 * @type {string}
 */
let subConverterProtocol = 'https';

export default {
	async fetch(request, env) {
		const userAgentHeader = request.headers.get('User-Agent');
		const userAgent = userAgentHeader ? userAgentHeader.toLowerCase() : "null";
		const url = new URL(request.url);
		const token = url.searchParams.get('token');
		adminToken = env.TOKEN || adminToken;
		guestToken = env.GUESTTOKEN || env.GUEST || guestToken;
		subConverterApiHost = env.SUBAPI || subConverterApiHost;
		subConverterConfigUrl = env.SUBCONFIG || subConverterConfigUrl;
		subscriptionFileName = env.SUBNAME || subscriptionFileName;
		subscriptionUpdateIntervalHours = parseInt(env.SUBUPTIME || subscriptionUpdateIntervalHours, 10);
		const warpSources = env.WARP || '';

		if (subConverterApiHost.includes("://")) {
			const [protocol, ...hostParts] = subConverterApiHost.split("://");
			subConverterProtocol = protocol;
			subConverterApiHost = hostParts.join("://");
		}

		const currentTimestamp = Math.floor(Date.now() / 1000);
		const todayStartTimestamp = Math.floor(new Date().setHours(0, 0, 0, 0) / 1000);
		const dailyTempToken = await generateLegacyMD5(`${adminToken}${todayStartTimestamp}`);

		if (!guestToken) {
			guestToken = await generateLegacyMD5(adminToken);
		}
		const guestTokenReadOnly = guestToken;

		const allowedTokens = [adminToken, dailyTempToken, guestTokenReadOnly];
		const isTokenValid = allowedTokens.includes(token);
		const isAdminPath = url.pathname === `/${adminToken}` || url.pathname.startsWith(`/${adminToken}/`);

		const isSubscriptionPath = url.pathname === '/sub';
		const isRootPath = url.pathname === '/';

		const isAuthenticated = isAdminPath || (isTokenValid && (isSubscriptionPath || isRootPath));

		if (!isAuthenticated && url.pathname !== '/favicon.ico') {
			if (env.URL302) return Response.redirect(env.URL302, 302);
			if (env.URL) return await proxyRequest(env.URL, url);
			return new Response(null, { status: 403 });
		}

		const isBrowser = userAgent.includes('mozilla');
		const showAdminPage = isBrowser && token === adminToken && (isRootPath || isAdminPath && url.search === '');

		if (env.KV && showAdminPage) {
			await migrateKvKey(env, 'LINK.txt');
			return await handleAdminPage(request, env, 'LINK.txt', guestTokenReadOnly);
		}

		let sources = defaultSources;
		let subscriptionUrls = [];
		let manualNodes = '';

		if (env.KV) {
			await migrateKvKey(env, 'LINK.txt');
			sources = await env.KV.get('LINK.txt') || defaultSources;
		} else {
			sources = env.LINK || defaultSources;
			if (env.LINKSUB) {
				subscriptionUrls = await parseUrlList(env.LINKSUB);
			}
		}

		const allParsedSources = await parseUrlList(sources + '\n' + subscriptionUrls.join('\n'));

		let fetchedSubscriptionUrls = [];
		for (const item of allParsedSources) {
			if (item.startsWith('http://') || item.startsWith('https://')) {
				fetchedSubscriptionUrls.push(item);
			} else if (item.trim()) {
				manualNodes += item + '\n';
			}
		}
		subscriptionUrls = [...new Set(fetchedSubscriptionUrls)];

		let outputFormat = 'base64';
		if (userAgent.includes('clash') || (url.searchParams.has('clash') && !userAgent.includes('subconverter'))) {
			outputFormat = 'clash';
		} else if (userAgent.includes('sing-box') || userAgent.includes('singbox') || ((url.searchParams.has('sb') || url.searchParams.has('singbox')) && !userAgent.includes('subconverter'))) {
			outputFormat = 'singbox';
		} else if (userAgent.includes('surge') || (url.searchParams.has('surge') && !userAgent.includes('subconverter'))) {
			outputFormat = 'surge';
		} else if (userAgent.includes('quantumult%20x') || userAgent.includes('quantumult x') || (url.searchParams.has('quanx') && !userAgent.includes('subconverter'))) {
			outputFormat = 'quanx';
		} else if (userAgent.includes('loon') || (url.searchParams.has('loon') && !userAgent.includes('subconverter'))) {
			outputFormat = 'loon';
		}

		if (url.searchParams.has('b64') || url.searchParams.has('base64')) outputFormat = 'base64';
		else if (url.searchParams.has('clash')) outputFormat = 'clash';
		else if (url.searchParams.has('sb') || url.searchParams.has('singbox')) outputFormat = 'singbox';
		else if (url.searchParams.has('surge')) outputFormat = 'surge';
		else if (url.searchParams.has('quanx')) outputFormat = 'quanx';
		else if (url.searchParams.has('loon')) outputFormat = 'loon';

		let fetchUASuffix = 'v2rayn';
		if (url.searchParams.has('clash')) fetchUASuffix = 'clash';
		else if (url.searchParams.has('singbox')) fetchUASuffix = 'singbox';
		else if (url.searchParams.has('surge')) fetchUASuffix = 'surge';
		else if (url.searchParams.has('quanx')) fetchUASuffix = 'Quantumult%20X';
		else if (url.searchParams.has('loon')) fetchUASuffix = 'Loon';

		const [fetchedNodesContent, fetchedUrlString] = await fetchSubscriptionContents(subscriptionUrls, request, fetchUASuffix, userAgentHeader);
		let combinedNodes = manualNodes + fetchedNodesContent.join('\n');

		let warpNodeString = '';
		let warpUrlString = '';
		if (warpSources) {
			const parsedWarpSources = await parseUrlList(warpSources);
			parsedWarpSources.forEach(item => {
				if (item.startsWith('http')) {
					warpUrlString += (warpUrlString ? '|' : '') + item;
				} else if (item.trim()) {
					warpNodeString += item + '\n';
				}
			});
			combinedNodes += '\n' + warpNodeString;
		}

		const cleanedNodes = combinedNodes.replace(/\r\n/g, '\n').trim();
		const uniqueLines = new Set(cleanedNodes.split('\n').filter(line => line.trim() !== ''));
		const finalNodesString = [...uniqueLines].join('\n');

		let base64EncodedNodes;
		try {
			const utf8Bytes = new TextEncoder().encode(finalNodesString);
			const binaryString = String.fromCharCode(...utf8Bytes);
			base64EncodedNodes = btoa(binaryString);
		} catch (e) {
			console.error("Base64 编码失败:", e);
			return new Response("服务器内部错误：无法编码订阅内容。", { status: 500 });
		}

		if (outputFormat === 'base64' || token === dailyTempToken) {
			const nowMs = Date.now();
			const expireSec = Math.floor(expireTimestamp / 1000);
			const remainingRatio = expireTimestamp > nowMs ? (expireTimestamp - nowMs) / expireTimestamp : 0;
			const uploadDownloadBytes = Math.floor((remainingRatio * totalDataTB * 1099511627776) / 2);
			const totalBytes = totalDataTB * 1099511627776;
			const subscriptionUserInfo = `upload=${uploadDownloadBytes}; download=${uploadDownloadBytes}; total=${totalBytes}; expire=${expireSec}`;

			return new Response(base64EncodedNodes, {
				headers: {
					"content-type": "text/plain; charset=utf-8",
					"Profile-Update-Interval": `${subscriptionUpdateIntervalHours}`,
				}
			});
		} else {
			const converterInputUrl = `${url.origin}/${dailyTempToken}?token=${dailyTempToken}`
								  + (fetchedUrlString ? '|' + fetchedUrlString : '')
								  + (warpUrlString ? '|' + warpUrlString : '');
			const encodedInput = encodeURIComponent(converterInputUrl);
			const encodedConfig = encodeURIComponent(subConverterConfigUrl);

			let targetSubConverterUrl = '';
			switch (outputFormat) {
				case 'clash':
					targetSubConverterUrl = `${subConverterProtocol}://${subConverterApiHost}/sub?target=clash&url=${encodedInput}&insert=false&config=${encodedConfig}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
					break;
				case 'singbox':
					targetSubConverterUrl = `${subConverterProtocol}://${subConverterApiHost}/sub?target=singbox&url=${encodedInput}&insert=false&config=${encodedConfig}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
					break;
				case 'surge':
					targetSubConverterUrl = `${subConverterProtocol}://${subConverterApiHost}/sub?target=surge&ver=4&url=${encodedInput}&insert=false&config=${encodedConfig}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
					break;
				case 'quanx':
					targetSubConverterUrl = `${subConverterProtocol}://${subConverterApiHost}/sub?target=quanx&url=${encodedInput}&insert=false&config=${encodedConfig}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&udp=true`;
					break;
				case 'loon':
					targetSubConverterUrl = `${subConverterProtocol}://${subConverterApiHost}/sub?target=loon&url=${encodedInput}&insert=false&config=${encodedConfig}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false`;
					break;
				default:
					console.warn(`未知的订阅格式请求 '${outputFormat}', 回退到 base64。`);
					return new Response(base64EncodedNodes, { headers: { "content-type": "text/plain; charset=utf-8", "Profile-Update-Interval": `${subscriptionUpdateIntervalHours}` } });
			}

			try {
				const converterResponse = await fetch(targetSubConverterUrl, {
					headers: { 'User-Agent': userAgentHeader }
				});
				if (!converterResponse.ok) {
					console.error(`订阅转换 API 请求失败 (${targetSubConverterUrl}): ${converterResponse.status} ${converterResponse.statusText}`);
					const errorBody = await converterResponse.text();
					console.error('转换 API 错误响应:', errorBody);
					return new Response(base64EncodedNodes, { headers: { "content-type": "text/plain; charset=utf-8", "Profile-Update-Interval": `${subscriptionUpdateIntervalHours}` } });
				}

				let converterContent = await converterResponse.text();

				if (outputFormat === 'clash') {
					converterContent = applyClashFixes(converterContent);
				}

				const nowMs = Date.now();
				const expireSec = Math.floor(expireTimestamp / 1000);
				const remainingRatio = expireTimestamp > nowMs ? (expireTimestamp - nowMs) / expireTimestamp : 0;
				const uploadDownloadBytes = Math.floor((remainingRatio * totalDataTB * 1099511627776) / 2);
				const totalBytes = totalDataTB * 1099511627776;
				const subscriptionUserInfo = `upload=${uploadDownloadBytes}; download=${uploadDownloadBytes}; total=${totalBytes}; expire=${expireSec}`;

				return new Response(converterContent, {
					headers: {
						"Content-Disposition": `attachment; filename*=utf-8''${encodeURIComponent(subscriptionFileName)}`,
						"content-type": "text/plain; charset=utf-8",
						"Profile-Update-Interval": `${subscriptionUpdateIntervalHours}`,
					},
				});
			} catch (error) {
				console.error("请求订阅转换 API 时出错:", error);
				return new Response(base64EncodedNodes, { headers: { "content-type": "text/plain; charset=utf-8", "Profile-Update-Interval": `${subscriptionUpdateIntervalHours}` } });
			}
		}
	}
};

async function parseUrlList(inputString) {
	if (!inputString) return [];
	const cleaned = inputString.replace(/[\t"'|\r\n]+/g, ',').replace(/,+/g, ',');
	const trimmed = cleaned.replace(/^,|,$/g, '');
	return trimmed.split(',').map(s => s.trim()).filter(s => s);
}

function base64Decode(base64Str) {
	try {
		const binaryString = atob(base64Str);
		const bytes = new Uint8Array(binaryString.length);
		for (let i = 0; i < binaryString.length; i++) {
			bytes[i] = binaryString.charCodeAt(i);
		}
		return new TextDecoder().decode(bytes);
	} catch (e) {
		console.error("Base64 解码失败:", e, "输入字符串 (前100):", base64Str.substring(0, 100) + (base64Str.length > 100 ? "..." : ""));
		return '';
	}
}

async function generateLegacyMD5(text) {
	try {
		const encoder = new TextEncoder();

		const firstPassBuffer = await crypto.subtle.digest('MD5', encoder.encode(text));
		const firstPassArray = Array.from(new Uint8Array(firstPassBuffer));
		const firstHex = firstPassArray.map(b => b.toString(16).padStart(2, '0')).join('');

		const middlePart = firstHex.slice(7, 27);

		const secondPassBuffer = await crypto.subtle.digest('MD5', encoder.encode(middlePart));
		const secondPassArray = Array.from(new Uint8Array(secondPassBuffer));
		const secondHex = secondPassArray.map(b => b.toString(16).padStart(2, '0')).join('');

		return secondHex.toLowerCase();
	} catch (error) {
		console.error("生成 Legacy MD5 哈希时出错:", error);
		return '';
	}
}

function applyClashFixes(clashContent) {
	try {
		if (clashContent.includes('type: wireguard') && !clashContent.includes('remote-dns-resolve:')) {
			let lines;
			if (clashContent.includes('\r\n')) {
				lines = clashContent.split('\r\n');
			} else {
				lines = clashContent.split('\n');
			}

			let result = "";
			for (let line of lines) {
				if (line.includes('type: wireguard')) {
					const 备改内容 = `, mtu: 1280, udp: true`;
					const 正确内容 = `, mtu: 1280, remote-dns-resolve: true, udp: true`;
					result += line.replace(new RegExp(备改内容, 'g'), 正确内容) + '\n';
				} else {
					result += line + '\n';
				}
			}

			clashContent = result;
		}
	} catch (error) {
		console.error("应用 Clash 修复时出错:", error);
	}
	return clashContent;
}

async function proxyRequest(targetBaseUrl, originalUrl) {
	try {
		const target = new URL(targetBaseUrl);
		target.pathname = originalUrl.pathname;
		target.search = originalUrl.search;
		const finalTargetUrl = target.toString();

		const headers = new Headers();
		const originalUserAgent = request.headers.get('User-Agent');
		if (originalUserAgent) {
			headers.set('User-Agent', originalUserAgent);
		}
		headers.set('X-Forwarded-For', request.headers.get('CF-Connecting-IP') || '');

		const response = await fetch(finalTargetUrl, {
			method: request.method,
			headers: headers,
			body: (request.method === 'POST' || request.method === 'PUT') ? request.body : null,
			redirect: 'follow'
		});

		return response;

	} catch (error) {
		console.error(`代理请求到 ${targetBaseUrl} 时出错:`, error);
		return new Response("代理请求失败。", { status: 502 });
	}
}

async function fetchSubscriptionContents(urls, originalRequest, uaSuffix, originalUA) {
	if (!urls || urls.length === 0) {
		return [[], ''];
	}
	const uniqueUrls = [...new Set(urls)];

	const promises = uniqueUrls.map(url =>
		fetchUrlWithCustomUA(url, uaSuffix, originalUA)
			.then(content => ({ url, content }))
			.catch(error => {
				console.warn(`获取订阅内容失败: ${url}, 原因: ${error.message}`);
				return { url, content: null };
			})
	);

	let results;
	try {
		const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('获取订阅内容超时 (5 秒)')), 5000));
		results = await Promise.race([Promise.allSettled(promises), timeoutPromise]);
		if (results instanceof Error) throw results;
	} catch (error) {
		console.error('获取订阅内容时出错或超时:', error);
		return [[], ''];
	}

	const successfulContents = [];
	const successfulUrls = [];

	results.forEach(result => {
		if (result.status === 'fulfilled' && result.value && result.value.content !== null) {
			successfulContents.push(result.value.content);
			successfulUrls.push(result.value.url);
		} else if (result.status === 'rejected') {
		}
	});

	return [successfulContents, successfulUrls.join('|')];
}

async function fetchUrlWithCustomUA(targetUrl, uaSuffix, originalUA) {
	const customUA = `${atob('djJyYXlOLzYuNDU=')} cmliu/CF-Workers-SUB ${uaSuffix}(${originalUA})`;

	const MAX_RETRIES = 1;
	let attempts = 0;

	while (attempts <= MAX_RETRIES) {
		try {
			const response = await fetch(targetUrl, {
				method: 'GET',
				headers: { 'User-Agent': customUA },
				redirect: 'follow',
				signal: AbortSignal.timeout(3000)
			});

			if (!response.ok) {
				throw new Error(`HTTP 错误 ${response.status} for ${targetUrl}`);
			}

			const content = await response.text();

			if (isValidBase64(content)) {
				const decoded = base64Decode(content);
				if (decoded.includes('://') || decoded.includes('server=') || decoded.trim().startsWith('{') || decoded.includes('proxies:')) {
					return decoded;
				}
			}
			return content;

		} catch (error) {
			attempts++;
			console.warn(`第 ${attempts} 次尝试获取 ${targetUrl} 失败: ${error.message}`);
			if (attempts > MAX_RETRIES || error.name === 'AbortError') {
				throw error;
			}
		}
	}
	throw new Error(`获取 ${targetUrl} 在 ${MAX_RETRIES + 1} 次尝试后失败。`);
}

function isValidBase64(str) {
	if (!str || typeof str !== 'string') return false;
	const cleanedStr = str.replace(/\s/g, '');
	if (cleanedStr.length === 0 || cleanedStr.length % 4 !== 0) return false;
	const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
	if (!base64Regex.test(cleanedStr)) return false;
	try {
		atob(cleanedStr);
		return true;
	} catch (e) {
		return false;
	}
}

async function migrateKvKey(env, keyName) {
	if (!env.KV) return false;
	const oldKey = `/${keyName}`;
	const newKey = keyName;
	const migrationFlagKey = `${keyName}_MIGRATED_FLAG`;

	try {
		const migrationChecked = await env.KV.get(migrationFlagKey);
		if (migrationChecked === 'true') {
			return false;
		}

		const oldData = await env.KV.get(oldKey);
		const newData = await env.KV.get(newKey);

		if (oldData && !newData) {
			console.log(`正在迁移 KV 键: 从 '${oldKey}' 到 '${newKey}'...`);
			await env.KV.put(newKey, oldData);
			await env.KV.delete(oldKey);
			await env.KV.put(migrationFlagKey, 'true');
			console.log("KV 键迁移完成。");
			return true;
		} else {
			await env.KV.put(migrationFlagKey, 'true');
			return false;
		}
	} catch (error) {
		console.error("检查或迁移 KV 键时出错:", error);
		return false;
	}
}

async function handleAdminPage(request, env, kvKey, guestTokenReadOnly) {
	const url = new URL(request.url);
	let message = '';
	let messageType = 'info';

	try {
		if (request.method === "POST") {
			if (!env.KV) {
				return new Response("错误: 未绑定 KV 命名空间。", { status: 500 });
			}
			try {
				const contentType = request.headers.get('content-type');
				let contentToSave = '';
				if (contentType && contentType.includes('application/x-www-form-urlencoded')) {
					const formData = await request.formData();
					contentToSave = formData.get('content') || '';
					message = "列表已成功更新！";
				} else {
					contentToSave = await request.text();
					message = "列表已成功更新 (纯文本模式)！";
				}
				await env.KV.put(kvKey, contentToSave.trim());
				messageType = 'success';
			} catch (error) {
				console.error('保存 KV 时发生错误:', error);
				message = "保存失败: " + error.message;
				messageType = 'error';
			}
		}

		let currentKvContent = '';
		let kvAvailable = !!env.KV;

		if (kvAvailable) {
			try {
				currentKvContent = await env.KV.get(kvKey) || '';
			} catch (error) {
				console.error('读取 KV 时发生错误:', error);
				currentKvContent = '读取订阅源列表时出错: ' + error.message;
				message = '无法加载当前列表内容。';
				messageType = 'error';
			}
		} else {
			message = '未绑定 KV 命名空间，无法编辑列表。当前使用的是默认源。';
			messageType = 'info';
		}

		const baseUrl = `https://${url.hostname}`;
		const adminBaseUrl = `${baseUrl}/${adminToken}`;
		const guestBaseUrl = `${baseUrl}/sub?token=${guestTokenReadOnly}`;

		const linkFormats = {
			auto: { name: "自适应订阅", param: "" },
			base64: { name: "Base64 订阅", param: "b64" },
			clash: { name: "Clash 订阅", param: "clash" },
			singbox: { name: "Sing-Box 订阅", param: "sb" },
			surge: { name: "Surge 订阅", param: "surge" },
			quanx: { name: "Quantumult X 订阅", param: "quanx" },
			loon: { name: "Loon 订阅", param: "loon" },
		};

		function generateLinkListHtml(base, isGuest = false) {
			let linksHtml = '';
			for (const key in linkFormats) {
				const format = linkFormats[key];
				let finalUrl = '';
				if (isGuest) {
					finalUrl = base + (format.param ? `&${format.param}` : '');
				} else {
					finalUrl = base + (format.param ? `?${format.param}` : '');
				}

				linksHtml += `
					<div class="link-item">
						<span class="link-name">${format.name}:</span>
						<div class="link-input-group">
							<input type="text" value="${finalUrl}" readonly>
							<button type="button" class="copy-btn" data-clipboard-text="${finalUrl}">复制</button>
						</div>
					</div>`;
			}
			return linksHtml;
		}

		const html = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>${subscriptionFileName} - 订阅管理</title>
	<style>
		:root {
			--primary-color: #0d6efd;
			--secondary-color: #6c757d;
			--bg-color: #f8f9fa;
			--card-bg: #ffffff;
			--text-color: #212529;
			--border-color: #dee2e6;
			--link-color: #0d6efd;
			--success-bg: #d1e7dd;
			--success-text: #0f5132;
			--success-border: #badbcc;
			--error-bg: #f8d7da;
			--error-text: #842029;
			--error-border: #f5c2c7;
			--info-bg: #cff4fc;
			--info-text: #055160;
			--info-border: #b6effb;
			--copy-btn-bg: #198754;
			--copy-btn-hover-bg: #157347;
			--copied-btn-bg: #ffca2c;
			--copied-btn-text: #000;
		}
		body {
			font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol";
			margin: 0;
			background-color: var(--bg-color);
			color: var(--text-color);
			line-height: 1.6;
			font-size: 16px;
		}
		.header {
			background-color: #212529;
			color: white;
			padding: 1rem 1.5rem;
			margin-bottom: 2rem;
			box-shadow: 0 2px 4px rgba(0,0,0,0.1);
		}
		.header h1 {
			margin: 0;
			font-size: 1.5rem;
			text-align: center;
			font-weight: 500;
		}
		.container {
			max-width: 960px;
			margin: 0 auto 2rem auto;
			padding: 0 1rem;
		}
		.card {
			background-color: var(--card-bg);
			border: 1px solid var(--border-color);
			border-radius: 0.375rem;
			box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
			margin-bottom: 1.5rem;
			overflow: hidden;
		}
		.card-header {
			padding: 1rem 1.25rem;
			border-bottom: 1px solid var(--border-color);
			background-color: #f8f9fa;
		}
		.card-header h2 {
			margin: 0;
			font-size: 1.25rem;
			font-weight: 500;
		}
		.card-body {
			padding: 1.25rem;
		}
		.tab-nav {
			display: flex;
			border-bottom: 1px solid var(--border-color);
			margin: 0 -1.25rem 1.25rem -1.25rem;
			padding: 0 1.25rem;
		}
		.tab-button {
			padding: 0.75rem 1rem;
			cursor: pointer;
			border: none;
			background-color: transparent;
			font-size: 1rem;
			color: var(--secondary-color);
			border-bottom: 3px solid transparent;
			margin-bottom: -1px;
			transition: color 0.2s ease, border-color 0.2s ease;
			font-weight: 500;
		}
		.tab-button:hover {
			color: var(--text-color);
		}
		.tab-button.active {
			color: var(--primary-color);
			border-bottom-color: var(--primary-color);
		}
		.tab-content { display: none; }
		.tab-content.active { display: block; }

		.link-item {
			margin-bottom: 1rem;
			padding-bottom: 1rem;
			border-bottom: 1px solid #f1f3f5;
		}
		.link-item:last-child { margin-bottom: 0; padding-bottom: 0; border-bottom: none; }
		.link-name { display: block; font-weight: 500; margin-bottom: 0.4rem; color: #495057; }
		.link-input-group { display: flex; align-items: center; gap: 0.5rem; }
		.link-input-group input[type="text"] {
			flex-grow: 1;
			padding: 0.5rem 0.75rem;
			border: 1px solid var(--border-color);
			border-radius: 0.25rem;
			font-size: 0.95rem;
			background-color: var(--bg-color);
			font-family: monospace;
		}
		.copy-btn {
			padding: 0.4rem 0.8rem;
			font-size: 0.875rem;
			background-color: var(--copy-btn-bg);
			color: white;
			border: none;
			border-radius: 0.25rem;
			cursor: pointer;
			transition: background-color 0.2s ease;
			white-space: nowrap;
		}
		.copy-btn:hover { background-color: var(--copy-btn-hover-bg); }
		.copy-btn.copied { background-color: var(--copied-btn-bg); color: var(--copied-btn-text); cursor: default; }

		label { display: block; margin-bottom: 0.5rem; font-weight: 500; }
		textarea {
			width: 100%;
			min-height: 350px;
			margin-bottom: 1rem;
			border: 1px solid var(--border-color);
			border-radius: 0.25rem;
			padding: 0.75rem;
			font-size: 14px;
			line-height: 1.5;
			box-sizing: border-box;
			resize: vertical;
			font-family: monospace;
		}
		.save-btn {
			padding: 0.6rem 1.2rem;
			background-color: var(--primary-color);
			color: white;
			border: none;
			border-radius: 0.25rem;
			cursor: pointer;
			font-size: 1rem;
			font-weight: 500;
			transition: background-color 0.2s ease;
		}
		.save-btn:hover { background-color: #0b5ed7; }

		.message { padding: 1rem 1.25rem; margin-bottom: 1.5rem; border: 1px solid transparent; border-radius: 0.375rem; font-size: 0.95rem; }
		.message.success { color: var(--success-text); background-color: var(--success-bg); border-color: var(--success-border); }
		.message.error { color: var(--error-text); background-color: var(--error-bg); border-color: var(--error-border); }
		.message.info { color: var(--info-text); background-color: var(--info-bg); border-color: var(--info-border); }

		footer { text-align: center; margin-top: 3rem; padding: 1.5rem 1rem; font-size: 0.875rem; color: var(--secondary-color); border-top: 1px solid var(--border-color); }
	</style>
</head>
<body>
	<header class="header">
		<h1>${subscriptionFileName} - 订阅管理</h1>
	</header>

	<div class="container">
		${message ? `<div class="message ${messageType}">${message}</div>` : ''}

		<div class="card">
			<div class="card-header">
				<h2>订阅链接</h2>
			</div>
			<div class="card-body">
				<div class="tab-nav">
					<button class="tab-button active" data-tab="admin-links">管理员订阅</button>
					<button class="tab-button" data-tab="guest-links">访客订阅</button>
				</div>

				<div id="admin-links" class="tab-content active">
					${generateLinkListHtml(adminBaseUrl, false)}
				</div>

				<div id="guest-links" class="tab-content">
					${guestTokenReadOnly ? generateLinkListHtml(guestBaseUrl, true) : '<p>未配置访客令牌 (请在 Cloudflare Worker 环境变量中设置 GUESTTOKEN 或 GUEST)。</p>'}
				</div>
			</div>
		</div>

		${kvAvailable ? `
		<div class="card">
			<div class="card-header">
				<h2>编辑订阅源 (${kvKey})</h2>
			</div>
			<div class="card-body">
				<form method="POST" action="">
					<label for="content">源列表 (每行一个链接或节点信息):</label>
					<textarea id="content" name="content" placeholder="在此输入订阅链接或节点信息，每行一个...\n例如:\nhttps://example.com/mysub\nvmess://...\ntrojan://..." spellcheck="false">${currentKvContent}</textarea>
					<button type="submit" class="save-btn">保存更改</button>
				</form>
			</div>
		</div>
		` : `
		<div class="card">
			<div class="card-header"><h2>提示</h2></div>
			<div class="card-body message info">
				<p><strong>注意:</strong> 未绑定名为 <strong>KV</strong> 的 KV 命名空间，无法在线编辑订阅源列表。</p>
				<p>当前使用的是环境变量或代码内置的默认源。如需编辑，请在 Cloudflare 后台绑定 KV 命名空间。</p>
			</div>
		</div>
		` }
	</div>

	<footer>
		Powered by Cloudflare Workers
	</footer>

	<script>
		const tabButtons = document.querySelectorAll('.tab-button');
		const tabContents = document.querySelectorAll('.tab-content');

		tabButtons.forEach(button => {
			button.addEventListener('click', () => {
				tabButtons.forEach(btn => btn.classList.remove('active'));
				button.classList.add('active');
				tabContents.forEach(content => content.classList.remove('active'));
				document.getElementById(button.getAttribute('data-tab')).classList.add('active');
			});
		});

		document.querySelectorAll('.copy-btn').forEach(button => {
			button.addEventListener('click', () => {
				const textToCopy = button.getAttribute('data-clipboard-text');
				navigator.clipboard.writeText(textToCopy).then(() => {
					const originalText = button.textContent;
					button.textContent = '已复制!';
					button.classList.add('copied');
					button.disabled = true;
					setTimeout(() => {
						button.textContent = originalText;
						button.classList.remove('copied');
						button.disabled = false;
					}, 1500);
				}).catch(err => {
					console.error('复制失败:', err);
					button.textContent = '失败';
					 setTimeout(() => { button.textContent = '复制'; }, 2000);
				});
			});
		});
	</script>
</body>
</html>`;

		return new Response(html, {
			headers: { "Content-Type": "text/html;charset=utf-8" }
		});
	} catch (error) {
		console.error('处理管理页面请求时发生严重错误:', error);
		return new Response("服务器内部错误: " + error.message, {
			status: 500,
			headers: { "Content-Type": "text/plain;charset=utf-8" }
		});
	}
}
