// 默认配置值
// 这些值可以在 Cloudflare Workers 的环境变量设置中被覆盖
let adminToken = 'auto'; // 管理员访问令牌，用于访问 Worker，请替换 'auto' 或通过环境变量 TOKEN 设置
let guestAccessToken = ''; // 访客访问令牌，可以是任意字符串或 UUID。通过环境变量 GUESTTOKEN 或 GUEST 设置
let subscriptionFileName = 'CF-Workers-SUB'; // 下载订阅文件时的默认文件名。通过环境变量 SUBNAME 设置
let subscriptionUpdateIntervalHours = 6; // 默认订阅更新间隔（小时）。通过环境变量 SUBUPTIME 设置
let subscriptionTotalDataTB = 99; // Subscription-Userinfo 响应头中的总流量默认值 (TB)。
let subscriptionExpireTimestamp = 4102329600000; // 默认过期时间戳 (例如, 2099-12-31)。

// 默认数据源: 节点链接 + 订阅链接
let defaultSources = `
https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray
https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt
https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt
https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2
https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/airport_sub_merge.txt
https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/sub_merge.txt
https://raw.githubusercontent.com/Pawdroid/Free-servers/refs/heads/main/sub
`; // 在此处添加默认源，用换行符分隔

let subscriptionUrls = []; // 用于存储解析后的订阅链接的数组
let subConverterBackend = "api.v1.mk"; // 订阅转换后端主机名。通过环境变量 SUBAPI 设置
let subConverterConfigUrl = "https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/config/ACL4SSR_Online_MultiCountry.ini"; // 默认订阅转换配置文件的 URL。通过环境变量 SUBCONFIG 设置
let subConverterProtocol = 'https'; // 订阅转换后端的协议 ('http' 或 'https')

// 输出格式常量
const FORMAT_BASE64 = 'base64';
const FORMAT_CLASH = 'clash';
const FORMAT_SINGBOX = 'singbox';
const FORMAT_SURGE = 'surge';
const FORMAT_QUANX = 'quanx';
const FORMAT_LOON = 'loon';

export default {
	/**
	 * 处理传入的请求。
	 * @param {Request} request 传入的请求对象。
	 * @param {object} env 环境变量和绑定。包含 KV, R2 等。
	 * @returns {Promise<Response>} 响应 Promise。
	 */
	async fetch(request, env) {
		const userAgentHeader = request.headers.get('User-Agent') || '';
		const userAgent = userAgentHeader.toLowerCase();
		const url = new URL(request.url);
		const urlToken = url.searchParams.get('token'); // 从查询字符串获取 token

		// --- 配置加载 ---
		// 从环境变量加载配置，覆盖默认值
		adminToken = env.TOKEN || adminToken;
		subConverterBackend = env.SUBAPI || subConverterBackend;
		subConverterConfigUrl = env.SUBCONFIG || subConverterConfigUrl;
		subscriptionFileName = env.SUBNAME || subscriptionFileName;
		subscriptionUpdateIntervalHours = parseInt(env.SUBUPTIME || subscriptionUpdateIntervalHours); // 确保是数字

		// 确定 subConverter 协议并清理后端主机名
		if (subConverterBackend.includes("://")) {
			const parts = subConverterBackend.split("://");
			subConverterProtocol = parts[0];
			subConverterBackend = parts[1];
		}

		// 基于 adminToken 和当前时间生成动态令牌 (每日轮换)
		const currentDate = new Date();
		currentDate.setHours(0, 0, 0, 0); // 当天开始时间
		const timeTemp = Math.ceil(currentDate.getTime() / 1000);
		const dailyToken = await generateHash(`${adminToken}${timeTemp}`); // 每日轮换令牌

		// 加载或生成访客访问令牌
		guestAccessToken = env.GUESTTOKEN || env.GUEST || guestAccessToken;
		if (!guestAccessToken) {
			guestAccessToken = await generateHash(adminToken); // 如果未设置，则从 adminToken 生成访客令牌
		}
		const guestSubscriptionToken = guestAccessToken; // 使用别名以提高清晰度

		// 计算 Subscription-Userinfo 响应头所需的剩余流量和过期时间
		const now = Date.now();
		const expire = Math.floor(subscriptionExpireTimestamp / 1000);
		// 避免除以零或负的时间差
		const remainingRatio = subscriptionExpireTimestamp > now ? (subscriptionExpireTimestamp - now) / subscriptionExpireTimestamp : 0;
		const uploadDownload = Math.floor((remainingRatio * subscriptionTotalDataTB * 1099511627776) / 2);
		const totalDataBytes = subscriptionTotalDataTB * 1099511627776;
		const subscriptionUserInfo = `upload=${uploadDownload}; download=${uploadDownload}; total=${totalDataBytes}; expire=${expire}`;

		// --- 身份验证检查 ---
		// 允许的令牌: 管理员令牌, 每日轮换令牌, 访客令牌
		const allowedTokens = [adminToken, dailyToken, guestSubscriptionToken];
		const isTokenValid = allowedTokens.includes(urlToken);
		// 允许的路径: /<adminToken>/* 或根路径 / 带有有效的查询参数令牌
		const isAdminPath = url.pathname.startsWith(`/${adminToken}`);
		// const isRootPathWithToken = url.pathname === '/' && isTokenValid; // 根路径需要 token 验证
		// 合并检查: 如果令牌有效 或 访问的是管理员路径 则授权通过
        // 调整: 根路径或 /sub 路径配合有效 token 也视为认证通过
        const isSubscriptionPathWithToken = (url.pathname === '/' || url.pathname === '/sub') && isTokenValid;
		const isAuthenticated = isTokenValid || isAdminPath || isSubscriptionPathWithToken;

		// 如果未通过身份验证
		if (!isAuthenticated && url.pathname !== '/favicon.ico') {
			// 如果配置了重定向或代理 URL，则执行相应操作，否则直接返回 403 Forbidden
			if (env.URL302) return Response.redirect(env.URL302, 302);
			if (env.URL) return await proxyRequest(env.URL, request); // 传递完整的 request 对象以获取 URL
			// 直接返回 403 状态码和简单文本
            return new Response("Forbidden: Access Denied", {
                status: 403,
                headers: { 'Content-Type': 'text/plain; charset=UTF-8' },
            });
		}

		// --- 已认证的访问 ---
		let currentSources = defaultSources; // 从默认源开始
		let kvLinkKey = 'LINK.txt'; // 在 KV 中存储源列表的键

		// 处理 KV 存储 (如果已启用)
			if (env.KV) {
			await migrateSourcesToKV(env, kvLinkKey); // 如果需要，将源从环境变量迁移到 KV

			// 如果 User-Agent 看起来像浏览器且没有查询参数，则显示 KV 编辑器
            // 并且路径是管理员路径或者根路径带有管理员令牌
            const showEditor = userAgent.includes('mozilla') && !url.search && (isAdminPath || (url.pathname === '/' && urlToken === adminToken));

			if (showEditor) {
				// 注意：KV 编辑器现在只处理 POST 请求用于保存，GET 请求显示编辑器页面
                if (request.method === 'POST') {
                    return await handleKvEditorRequest(request, env, kvLinkKey, guestSubscriptionToken); // 处理保存
				} else {
				    return await handleKvEditorRequest(request, env, kvLinkKey, guestSubscriptionToken); // 显示编辑器
				}
			} else {
				// 否则，从 KV 加载源，如果 KV 中没有则回退到默认值
				currentSources = await env.KV.get(kvLinkKey) || defaultSources;
			}
				} else {
			// 如果未使用 KV，则处理环境变量存储
			currentSources = env.LINK || defaultSources; // 从 ENV.LINK 加载主要源
			if (env.LINKSUB) { // 从 ENV.LINKSUB 加载额外的订阅 URL
				subscriptionUrls = await parseSources(env.LINKSUB);
			}
		}

		// 合并并解析所有源 (KV/ENV + 默认源 + LINKSUB)
		let allSourceLinks = await parseSources(currentSources + '\n' + subscriptionUrls.join('\n'));

		// 分离手动添加的节点和订阅 URL
		let manualNodes = "";
		let fetchedSubscriptionUrls = []; // 使用不同名称避免混淆
		for (let link of allSourceLinks) {
			if (link.toLowerCase().startsWith('http')) {
				fetchedSubscriptionUrls.push(link);
			} else if (link) { // 确保不是空的手动节点
				manualNodes += link + '\n';
			}
		}
		subscriptionUrls = fetchedSubscriptionUrls; // 更新主要的订阅 URL 列表

		// 根据 User-Agent 和查询参数确定输出格式
		const outputFormat = determineOutputFormat(userAgent, url);

		// --- 订阅获取和处理 ---
		let nodesData = manualNodes; // 从手动添加的节点开始
		// 生成订阅转换器输入的基础 URL
		// 内部获取路径使用 dailyToken 以防止暴露管理员/访客令牌
		let baseSubConverterUrlInput = `${url.origin}/${await generateHash(dailyToken)}?token=${dailyToken}`;

		// 从订阅 URL 获取内容
		const fetchUserAgentSuffix = getFetchUserAgentSuffix(url); // 确定获取订阅时使用的 UA 后缀
		const fetchedSubscriptionResult = await fetchSubscriptionContents(subscriptionUrls, request, fetchUserAgentSuffix, userAgentHeader);
		const fetchedNodes = fetchedSubscriptionResult[0].join('\n');
		const fetchedUrlsString = fetchedSubscriptionResult[1]; // 成功获取的 URL 字符串

		nodesData += '\n' + fetchedNodes; // 追加获取到的节点 (添加换行符分隔)
		if (fetchedUrlsString) { // 仅当成功获取到 URL 时才添加到转换器输入
            baseSubConverterUrlInput += "|" + fetchedUrlsString;
        }

		// 如果配置了 WARP 节点，则添加
		if (env.WARP) {
			const warpNodes = await parseSources(env.WARP);
            if (warpNodes.length > 0) {
                // 如果 WARP 配置是链接，添加到转换 URL；如果是节点信息，添加到 nodesData
                const warpIsUrl = warpNodes[0].toLowerCase().startsWith('http');
                if (warpIsUrl) {
                    baseSubConverterUrlInput += "|" + warpNodes.join("|");
                } else {
                    nodesData += '\n' + warpNodes.join('\n');
                }
            }
		}

		// --- 准备最终输出 ---
		// 删除重复节点 (首先确保行尾符一致)
		const cleanedNodesData = nodesData.replace(/\r\n/g, '\n').trim(); // 移除首尾空白
		const uniqueLines = new Set(cleanedNodesData.split('\n').filter(line => line.trim() !== '')); // 过滤空行
		const finalNodesData = [...uniqueLines].join('\n');

		// Base64 编码最终的节点列表
		let base64EncodedNodes;
		try {
			// 使用内置的 btoa 进行 Base64 编码
            // 需要处理 Unicode 字符
            const utf8Bytes = new TextEncoder().encode(finalNodesData);
            const binaryString = String.fromCharCode(...utf8Bytes);
			base64EncodedNodes = btoa(binaryString);
			} catch (e) {
			console.error("Base64 编码失败:", e);
			// 如果 btoa 意外失败，进行回退或错误处理
			return new Response("将数据编码为 Base64 时出错。", { status: 500 });
		}

		// --- 生成响应 ---
		// 如果格式是 base64 或是对原始组合列表的请求 (使用 daily token)
		if (outputFormat === FORMAT_BASE64 || urlToken === dailyToken) {
			return new Response(base64EncodedNodes, {
				headers: {
					"content-type": "text/plain; charset=utf-8",
					"Profile-Update-Interval": `${subscriptionUpdateIntervalHours}`,
					//"Subscription-Userinfo": subscriptionUserInfo, // 取消注释以启用
				}
			});
		}

		// 否则，使用订阅转换器
		let subConverterUrl;
		const encodedInputUrl = encodeURIComponent(baseSubConverterUrlInput);
		const encodedConfigUrl = encodeURIComponent(subConverterConfigUrl);

		// 根据格式构建相应的订阅转换器 URL
		switch (outputFormat) {
			case FORMAT_CLASH:
				subConverterUrl = `${subConverterProtocol}://${subConverterBackend}/sub?target=clash&url=${encodedInputUrl}&insert=false&config=${encodedConfigUrl}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
				break;
			case FORMAT_SINGBOX:
				subConverterUrl = `${subConverterProtocol}://${subConverterBackend}/sub?target=singbox&url=${encodedInputUrl}&insert=false&config=${encodedConfigUrl}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
				break;
			case FORMAT_SURGE:
				subConverterUrl = `${subConverterProtocol}://${subConverterBackend}/sub?target=surge&ver=4&url=${encodedInputUrl}&insert=false&config=${encodedConfigUrl}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
				break;
			case FORMAT_QUANX:
				subConverterUrl = `${subConverterProtocol}://${subConverterBackend}/sub?target=quanx&url=${encodedInputUrl}&insert=false&config=${encodedConfigUrl}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&udp=true`;
				break;
			case FORMAT_LOON:
				subConverterUrl = `${subConverterProtocol}://${subConverterBackend}/sub?target=loon&url=${encodedInputUrl}&insert=false&config=${encodedConfigUrl}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false`;
				break;
			default: // 如果 determineOutputFormat 正确则不应发生，但回退到 base64
				console.warn(`请求了未知的输出格式: ${outputFormat}，回退到 base64。`);
				return new Response(base64EncodedNodes, {
					headers: {
						"content-type": "text/plain; charset=utf-8",
						"Profile-Update-Interval": `${subscriptionUpdateIntervalHours}`,
						//"Subscription-Userinfo": subscriptionUserInfo, // 取消注释以启用
					}
				});
		}

		// 从后端获取转换后的订阅
		try {
			// console.log("SubConverter URL:", subConverterUrl); // 调试用
				const subConverterResponse = await fetch(subConverterUrl);

				if (!subConverterResponse.ok) {
				console.error(`从 subConverterUrl (${subConverterUrl}) 获取错误: ${subConverterResponse.status} ${subConverterResponse.statusText}`);
				const errorBody = await subConverterResponse.text();
                console.error("SubConverter 错误响应体:", errorBody);
				// 如果转换器失败，回退到 base64
				return new Response(base64EncodedNodes, {
					headers: {
						"content-type": "text/plain; charset=utf-8",
						"Profile-Update-Interval": `${subscriptionUpdateIntervalHours}`,
						//"Subscription-Userinfo": subscriptionUserInfo, // 取消注释以启用
					}
				});
			}

			let subConverterContent = await subConverterResponse.text();

			// 如果需要，应用特定修复 (例如, 对 Clash)
			if (outputFormat === FORMAT_CLASH) {
				subConverterContent = applyClashFixes(subConverterContent);
			}

			// 返回转换后的内容
			return new Response(subConverterContent, {
				headers: {
					"Content-Disposition": `attachment; filename*=utf-8''${encodeURIComponent(subscriptionFileName)}`,
					"content-type": "text/plain; charset=utf-8",
					"Profile-Update-Interval": `${subscriptionUpdateIntervalHours}`,
					//"Subscription-Userinfo": subscriptionUserInfo, // 取消注释以启用
				},
			});
		} catch (error) {
			console.error("订阅转换获取期间出错:", error);
			// 对任何获取错误回退到 base64
			return new Response(base64EncodedNodes, {
			headers: {
					"content-type": "text/plain; charset=utf-8",
					"Profile-Update-Interval": `${subscriptionUpdateIntervalHours}`,
					//"Subscription-Userinfo": subscriptionUserInfo, // 取消注释以启用
			}
		});
	}
}
};

// --- 辅助函数 ---

/**
 * 解析包含源（URL 或节点数据）的字符串，这些源由换行符、逗号、制表符或引号分隔，
 * 并将其转换为字符串数组。
 * @param {string} sourceString 包含源的输入字符串。
 * @returns {Promise<string[]>} 解析后的源数组。
 */
async function parseSources(sourceString) {
	if (!sourceString) return [];
	// 将各种分隔符替换为单个逗号，然后分割
	let cleanedString = sourceString.replace(/[\t"'|\r\n]+/g, ',').replace(/,+/g, ',');
	// 移除开头/结尾的逗号
	if (cleanedString.startsWith(',')) cleanedString = cleanedString.slice(1);
	if (cleanedString.endsWith(',')) cleanedString = cleanedString.slice(0, -1);
	// 分割成数组并过滤掉空字符串
	return cleanedString.split(',').map(s => s.trim()).filter(s => s);
}

/**
 * 生成输入文本的 MD5 哈希值。
 * 使用 Cloudflare Workers 中可用的 SubtleCrypto API。
 * @param {string} text 要哈希的文本。
 * @returns {Promise<string>} MD5 哈希的十六进制表示。
 */
async function generateHash(text) {
	const encoder = new TextEncoder();
	const data = encoder.encode(text);
	const hashBuffer = await crypto.subtle.digest('MD5', data);
	const hashArray = Array.from(new Uint8Array(hashBuffer)); // 将 buffer 转换为字节数组
	const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join(''); // 将字节转换为十六进制字符串
	return hashHex;
}

/**
 * 对 Clash 配置内容应用特定修复。
 * 当前仅作为示例，需要根据实际需求调整。
 * @param {string} content 原始 Clash 配置内容。
 * @returns {string} 修改后的 Clash 配置内容。
 */
function applyClashFixes(content) {
	// 示例修复: 如果需要，重命名特定的代理组
	// 这是一个占位符，根据实际需要的修复进行调整
	try {
		// 示例: 替换已知的有问题组名
		// content = content.replace(/旧组名/g, '新组名');

		// 示例: 确保某种结构或在缺少时添加强制字段
		// (这通常需要 YAML 解析，没有外部库会很复杂)
		// 对于简单的文本替换:
		content = content.replace('挂载配置处理', '外部配置处理'); // 示例重命名
        content = content.replace('节点选择', '手动选择'); // 另一个示例
        // 修复 WireGuard (如果 subconverter 未正确添加 remote-dns-resolve)
        if (content.includes('- name:') && content.includes('type: wireguard') && !content.includes('remote-dns-resolve')) {
            content = content.replace(/(type: wireguard\s*\n\s*.*?)\n/gs, (match, group1) => {
                if (group1.includes('remote-dns-resolve:')) return match; // Already has it
                // Add remote-dns-resolve: true before other potential keys
                return group1.replace('udp: true', 'remote-dns-resolve: true, udp: true') + '\n';
            });
        }

	} catch (error) {
		console.error("应用 Clash 修复时出错:", error);
		// 如果修复失败，返回原始内容
	}
	return content;
}

/**
 * 将传入请求代理到目标 URL。
 * 复制基本信息。
 * @param {string} targetProxyUrl 要代理到的基础 URL 字符串。
 * @param {Request} originalRequest 原始请求对象。
 * @returns {Promise<Response>} 来自代理 URL 的响应。
 */
async function proxyRequest(targetProxyUrl, originalRequest) {
    try {
        const targetUrl = new URL(targetProxyUrl); // 解析基础目标 URL
        const newUrl = new URL(originalRequest.url); // 复制原始请求的 URL

        // 构建新的目标 URL，保留原始请求的路径和查询参数
        targetUrl.pathname = newUrl.pathname;
        targetUrl.search = newUrl.search;
        const finalTargetUrl = targetUrl.toString();

        // 准备代理请求的头部
        const headers = new Headers(originalRequest.headers); // 复制原始请求头
        headers.set('Host', targetUrl.host); // 设置正确的目标 Host
        headers.set('X-Forwarded-For', originalRequest.headers.get('CF-Connecting-IP') || '');
        headers.set('X-Forwarded-Proto', newUrl.protocol.slice(0, -1));
        // 可以根据需要删除或修改其他头部，例如 CF 特有的头部
        // headers.delete('cf-connecting-ip');
        // headers.delete('cf-ipcountry');
        // ...

		// console.log(`Proxying request to: ${finalTargetUrl}`); // 调试信息
        const response = await fetch(finalTargetUrl, {
            method: originalRequest.method,
            headers: headers,
            body: originalRequest.body, // 传递请求体
            redirect: 'manual' // 手动处理重定向，防止 Worker 内部循环
        });

        // 创建一个新的响应，复制状态码、状态文本和头部
        const newResponseHeaders = new Headers(response.headers);
        // 可以添加自定义头部
        newResponseHeaders.set('X-Proxied-By', 'Cloudflare-Worker');

        // 如果是重定向，修改 Location 头部
        if ([301, 302, 307, 308].includes(response.status)) {
            const location = newResponseHeaders.get('Location');
            if (location) {
                // 将重定向地址转换回原始域名
                const originalHost = new URL(originalRequest.url).host;
                const newLocation = location.replace(targetUrl.origin, `https://${originalHost}`);
                newResponseHeaders.set('Location', newLocation);
            }
        }

        return new Response(response.body, {
		status: response.status,
		statusText: response.statusText,
            headers: newResponseHeaders
        });

    } catch (error) {
        console.error(`代理请求到 ${targetProxyUrl} 时出错:`, error);
        return new Response("代理请求失败。", { status: 502 }); // Bad Gateway
    }
}

/**
 * 并发地从多个订阅 URL 获取内容。
 * @param {string[]} urls 订阅 URL 的数组。
 * @param {Request} request 原始传入请求对象。
 * @param {string} fetchUserAgentSuffix 用于获取订阅的 User-Agent 后缀。
 * @param {string} originalUserAgent 原始 User-Agent 标头。
 * @returns {Promise<[string[], string]>} 一个包含以下内容的元组：
 *          - 成功获取的订阅内容数组 (作为字符串)。
 *          - 成功获取的 URL 字符串，用 '|' 分隔。
 */
async function fetchSubscriptionContents(urls, request, fetchUserAgentSuffix, originalUserAgent) {
	if (!urls || urls.length === 0) {
		return [[], ''];
	}

    const uniqueUrls = [...new Set(urls)]; // 获取前去重

	const fetchPromises = uniqueUrls.map(url =>
		fetchUrlContent(request, url, fetchUserAgentSuffix, originalUserAgent)
			.then(content => ({ url, content })) // 跟踪 URL 和内容
			.catch(error => {
				console.warn(`获取订阅失败 ${url}:`, error.message);
				return { url, content: null }; // 表明失败，但不中断 Promise.all
			})
	);

    // 添加超时控制
    const timeoutPromise = new Promise((_, reject) =>
        setTimeout(() => reject(new Error('获取订阅内容超时 (5 秒)')), 5000) // 5 秒超时
    );

	// const results = await Promise.all(fetchPromises);
    // 使用 Promise.race 包含超时
    let results;
    try {
         results = await Promise.race([Promise.all(fetchPromises), timeoutPromise]);
         // 如果是超时，results 会是 Error 对象
         if (results instanceof Error) throw results;
    } catch (error) {
        console.error("获取订阅内容时出错或超时:", error);
        // 返回空结果，让主流程继续，但可能没有获取到任何订阅
        return [[], ''];
    }


	const successfulContents = [];
	const successfulUrls = [];

	for (const result of results) {
        // 确保 result 不是 null 或 undefined (如果 Promise.all 被中断)
		if (result && result.content !== null) {
			successfulContents.push(result.content);
			successfulUrls.push(result.url);
		}
	}

	return [successfulContents, successfulUrls.join('|')];
}

/**
 * 从单个 URL 获取内容，处理潜在的 Base64 编码。
 * @param {Request} request 原始请求 (如果需要上下文/标头)。
 * @param {string} targetUrl 要获取的 URL。
 * @param {string} userAgentSuffix User-Agent 标头的后缀。
 * @param {string} originalUserAgent 原始 User-Agent。
 * @returns {Promise<string>} 获取到的 (并可能解码的) 内容。
 */
async function fetchUrlContent(request, targetUrl, userAgentSuffix, originalUserAgent) {
	// 获取时使用特定的 UA 以避免循环或检测问题
	// 使用一个通用的、不太可能被 WAF 拦截的 UA
	const fetchUserAgent = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36`;
	// const fetchUserAgent = userAgentSuffix
	// 	? `${atob('djJyYXlOLzYuNDU=')} cmliu/CF-Workers-SUB ${userAgentSuffix}(${originalUserAgent})` // 之前的 UA
	// 	: originalUserAgent || 'CloudflareWorkerFetcher/1.0';

	const MAX_RETRIES = 1; // 限制重试次数
	let attempts = 0;

	while (attempts <= MAX_RETRIES) {
		try {
			const response = await fetch(targetUrl, {
				method: 'GET',
				headers: { 'User-Agent': fetchUserAgent },
				redirect: 'follow', // 跟随重定向
                signal: AbortSignal.timeout(3000) // 添加 3 秒超时
			});

			if (!response.ok) {
				throw new Error(`HTTP 错误 ${response.status} for ${targetUrl}`);
			}

            // 检查 Content-Type，优先处理文本类型
            const contentType = response.headers.get('content-type') || '';
			const content = await response.text();

            // 如果内容看起来像 Base64 并且不是明确的文本类型，尝试解码
			if (!contentType.includes('text') && !contentType.includes('json') && isValidBase64(content)) {
                const decoded = base64Decode(content);
                // 基本检查解码结果是否有意义 (例如, 包含常见的协议前缀或 JSON 结构)
                if (decoded.includes('://') || decoded.includes('server=') || decoded.trim().startsWith('{') || decoded.includes('proxies:')) {
				    return decoded; // 返回解码后的内容
                }
			}
			// 否则返回原始内容
            return content;

		} catch (error) {
			attempts++;
			console.warn(`尝试 ${attempts} 失败 ${targetUrl}: ${error.message}`);
			if (attempts > MAX_RETRIES || error.name === 'AbortError') { // 也处理 AbortError
				throw error; // 重试次数用尽或明确超时后重新抛出错误
			}
			// 可选: 在重试前添加短暂延迟
			// await new Promise(resolve => setTimeout(resolve, 100));
		}
	}
    // 如果循环/重抛逻辑正常，则不应到达此处
    throw new Error(`在 ${MAX_RETRIES + 1} 次尝试后获取 ${targetUrl} 失败。`);
}

/**
 * 检查字符串是否可能是有效的 Base64。
 * 这是一个基本检查，可能会有误报/漏报。
 * @param {string} str 要检查的字符串。
 * @returns {boolean} 如果看起来是 Base64 则为 true，否则为 false。
 */
function isValidBase64(str) {
	if (!str || typeof str !== 'string') {
		return false;
	}
    const cleanStr = str.replace(/\s/g, ''); // 移除空白字符
    // 检查长度是否为 4 的倍数
    if (cleanStr.length === 0 || cleanStr.length % 4 !== 0) {
		return false;
	}
	// 正则表达式检查字符串是否仅包含 Base64 字符 (A-Z, a-z, 0-9, +, /)
    // 和可选的填充符 (=)。
	const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/; // 更严格的正则，允许末尾最多两个=
	if (!base64Regex.test(cleanStr)) {
	return false;
}
    // 进一步检查: 尝试解码。如果抛出异常，则可能不是有效的 Base64。
    try {
        atob(cleanStr);
        return true;
    } catch (e) {
        // console.log("Invalid base64 check:", e.message); // Debugging
        return false;
    }
}

/**
 * 将源列表从环境变量 (LINK, LINKSUB) 迁移到 KV 存储。
 * 这旨在运行一次或偶尔运行。
 * @param {object} env 包含 KV 绑定和环境变量的环境对象。
 * @param {string} [kvKey='LINK.txt'] 用于存储组合列表的 KV 键。
 */
async function migrateSourcesToKV(env, kvKey = 'LINK.txt') {
	const needsMigrationKey = `${kvKey}_MIGRATED_V2`; // 使用新 Key 以便重新触发迁移（如果需要）

	// 检查是否已完成迁移
	const alreadyMigrated = await env.KV.get(needsMigrationKey);
	if (alreadyMigrated === 'true') { // 显式检查 'true'
		// console.log("源已迁移到 KV。");
		return;
	}

	// 检查源环境变量是否存在
	const linkEnv = env.LINK;
	const linksubEnv = env.LINKSUB;

	if (linkEnv || linksubEnv) {
		console.log(`正在将源从 ENV (LINK, LINKSUB) 迁移到 KV 键 '${kvKey}'...`);
		try {
			// 获取当前的 KV 值 (如果有)
			const currentKvValue = await env.KV.get(kvKey) || "";

			// 解析环境变量
			const envLinks = await parseSources(linkEnv || "");
			const envSubLinks = await parseSources(linksubEnv || "");

			// 合并当前的 KV、LINK、LINKSUB，确保唯一性
            // 使用 Set 自动去重
			const combinedSet = new Set([
				...(await parseSources(currentKvValue)), // 现有 KV 内容
				...envLinks,
				...envSubLinks
			]);

			const combinedSources = [...combinedSet].join('\n');

			// 将组合列表存储在 KV 中
			await env.KV.put(kvKey, combinedSources);
			// 将迁移标记为完成
			await env.KV.put(needsMigrationKey, 'true'); // 存储 'true'

			console.log(`迁移成功。组合源已存储在 KV 键 '${kvKey}' 中。`);
			// 可选: 如果需要，在成功迁移后清除环境变量，
			// 但这不能从 Worker 本身完成。建议用户手动移除它们。
			console.warn("验证迁移后，请从您的 Worker 设置中移除 LINK 和 LINKSUB 环境变量。");

			} catch (error) {
			console.error("源向 KV 迁移期间出错:", error);
		}
	} else {
		// console.log("未找到用于迁移的 LINK 或 LINKSUB 环境变量。");
		// 如果没有源环境变量，仍然标记为已迁移，以防止重复检查
        await env.KV.put(needsMigrationKey, 'true'); // 存储 'true'
	}
}

/**
 * 处理对 KV 源列表编辑器的请求 (HTML 界面)。
 * 允许查看和更新存储在 KV 命名空间中的源列表。
 * @param {Request} request 传入的请求。
 * @param {object} env 包含 KV 绑定的环境对象。
 * @param {string} [kvKey='LINK.txt'] 源列表的 KV 键。
 * @param {string} guestToken 用于显示的访客访问令牌。
 * @returns {Promise<Response>} 编辑器的 HTML 响应或更新确认。
 */
async function handleKvEditorRequest(request, env, kvKey = 'LINK.txt', guestToken) {
	const url = new URL(request.url);
	let message = '';
    let messageType = 'info'; // 'success', 'error', 'info'

	// 处理 POST 请求 (更新列表)
	if (request.method === 'POST') {
        // 检查 Content-Type 是否为 application/x-www-form-urlencoded
        const contentType = request.headers.get('content-type');
        if (contentType && contentType.includes('application/x-www-form-urlencoded')) {
            try {
                const formData = await request.formData();
                const newContent = formData.get('content') || '';
                await env.KV.put(kvKey, newContent.trim());
                message = '列表已成功更新！';
                messageType = 'success';
                // 可选: 更新时发送 TG 通知 (功能已移除)
            } catch (error) {
                console.error("更新 KV 列表时出错:", error);
                message = '更新列表时出错：' + error.message;
                messageType = 'error';
            }
        } else {
             message = '无效的请求格式。请使用表单提交。';
             messageType = 'error';
        }
	}

	// 获取当前列表内容以供显示
	const currentContent = await env.KV.get(kvKey) || '';

    // 构建基础订阅 URL (使用 adminToken)
    const baseSubscriptionUrl = `${url.origin}/${adminToken}`; // 使用 adminToken 作为路径

	// 生成编辑器的 HTML 页面
	const html = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>订阅源编辑 - ${subscriptionFileName}</title>
	<style>
		body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 0; background-color: #f8f9fa; color: #212529; line-height: 1.6; }
		.navbar { background-color: #343a40; padding: 0.8rem 1.5rem; color: white; margin-bottom: 2rem; }
        .navbar h1 { margin: 0; font-size: 1.5rem; }
		.container { max-width: 900px; margin: 0 auto; padding: 2rem 1.5rem; background-color: #fff; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
		h2 { color: #343a40; border-bottom: 2px solid #dee2e6; padding-bottom: 0.6em; margin-top: 0; margin-bottom: 1.5rem; } /* Adjusted h2 margin */
        h3 { color: #343a40; margin-top: 2rem; margin-bottom: 1rem; }
		textarea { width: 100%; min-height: 300px; margin-bottom: 1.5em; border: 1px solid #ced4da; border-radius: 4px; padding: 0.75em; font-size: 14px; box-sizing: border-box; resize: vertical; }
		button { padding: 0.75em 1.5em; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 1em; transition: background-color 0.2s ease; vertical-align: middle; /* Align button */ }
		button:hover { background-color: #0056b3; }
        .copy-btn { background-color: #28a745; margin-left: 0.5em; /* Add some space */ }
        .copy-btn:hover { background-color: #218838; }
        .copy-btn.copied { background-color: #ffc107; color: #333; cursor: default; }
		.message { margin-bottom: 1.5em; padding: 1em; border-radius: 4px; border: 1px solid transparent; }
		.message.success { background-color: #d1e7dd; color: #0f5132; border-color: #badbcc; }
		.message.error { background-color: #f8d7da; color: #842029; border-color: #f5c2c7; }
        .message.info { background-color: #cff4fc; color: #055160; border-color: #b6effb; }
        .info-section { background-color: #e9ecef; padding: 1.5em; border-radius: 4px; margin-top: 2.5em; font-size: 0.9em; color: #495057; }
        .info-section h3 { margin-top: 0; color: #343a40; }
        .info-section ul { padding-left: 20px; margin-bottom: 0; }
        .token-display { background-color: #adb5bd; padding: 0.3em 0.6em; border-radius: 4px; font-family: monospace; word-break: break-all; color: #fff; display: inline-block; margin-top: 0.5em; }
        label { display: block; margin-bottom: 0.5rem; font-weight: 500; }
        select, input[type="text"] { width: 100%; padding: 0.5em; margin-bottom: 1em; border: 1px solid #ced4da; border-radius: 4px; box-sizing: border-box; font-size: 1em; }
        .form-group { margin-bottom: 1.5rem; }
        .url-display-group { display: flex; align-items: center; gap: 0.5em; }
        .url-display-group input { flex-grow: 1; margin-bottom: 0; /* Remove margin bottom from input in group */ }
        .url-display-group button { flex-shrink: 0; }
        footer { text-align: center; margin-top: 3rem; padding: 1rem; font-size: 0.85em; color: #6c757d; }
	</style>
</head>
<body>
    <div class="navbar">
        <h1>${subscriptionFileName} - 订阅源管理</h1>
    </div>
	<div class="container">
		${message ? `<div class="message ${messageType}">${message}</div>` : ''}

        <!-- 订阅链接生成区域 -->
        <h3>生成订阅链接</h3>
        <div class="form-group">
            <label for="formatSelect">选择订阅格式:</label>
            <select id="formatSelect">
                <option value="auto">自动判断 (默认)</option>
                <option value="base64">Base64</option>
                <option value="clash">Clash</option>
                <option value="singbox">Sing-Box</option>
                <option value="surge">Surge</option>
                <option value="quanx">Quantumult X</option>
                <option value="loon">Loon</option>
            </select>
        </div>
        <div class="form-group url-display-group">
            <input type="text" id="generatedUrl" readonly placeholder="选择格式后将在此显示订阅链接">
            <button type="button" id="copyUrlBtn" class="copy-btn">复制</button>
        </div>

		<!-- 编辑器区域 -->
        <h3>编辑订阅源列表 (${kvKey})</h3>
		<form method="POST" action="">
            <label for="content">源列表内容 (每行一个链接或节点信息):</label>
			<textarea id="content" name="content" placeholder="在此输入订阅链接或节点信息，每行一个...\n例如:\nhttps://example.com/mysub\nvmess://...\ntrojan://...">${currentContent}</textarea>
			<button type="submit">保存更改</button>
		</form>

        <!-- 说明区域 -->
        <div class="info-section">
            <h3>使用说明</h3>
            <ul>
                <li>在上方编辑器中管理您的订阅源和手动添加的节点。</li>
                <li>每行输入一个订阅链接（以 http 或 https 开头）或单个节点信息。</li>
                <li>支持 vmess, vless, trojan, ss, ssr, hy2, tuic 等常见格式的节点链接。</li>
                <li>编辑完成后，点击"保存更改"按钮。</li>
                <li>上方提供订阅链接生成功能，选择所需格式即可生成并复制。</li>
                <li>您的访客订阅令牌（只读，用于分享给他人使用订阅功能）: <span class="token-display">${guestToken || '未配置/生成'}</span></li>
                <li>分享访客链接格式为: <code>${url.origin}/sub?token=${guestToken || 'GUEST_TOKEN'}&lt;格式参数&gt;</code> (例如: <code>&clash</code>, <code>&base64</code>)</li>
            </ul>
        </div>
	</div>
    <footer>
        Powered by CF-Workers-SUB
    </footer>

	<script>
        const formatSelect = document.getElementById('formatSelect');
        const generatedUrlInput = document.getElementById('generatedUrl');
        const copyUrlBtn = document.getElementById('copyUrlBtn');
        const baseSubUrl = '${baseSubscriptionUrl}'; // 从后端获取基础 URL

        function updateGeneratedUrl() {
            const selectedFormat = formatSelect.value;
            let finalUrl = baseSubUrl;

            switch (selectedFormat) {
                case 'base64':
                    finalUrl += '?base64'; // 或者 ?b64
                    break;
                case 'clash':
                    finalUrl += '?clash';
                    break;
                case 'singbox':
                    finalUrl += '?sb'; // 或者 ?singbox
                    break;
                case 'surge':
                    finalUrl += '?surge';
                    break;
                case 'quanx':
                    finalUrl += '?quanx';
                    break;
                case 'loon':
                    finalUrl += '?loon';
                    break;
                case 'auto':
                default:
                    // 自动判断时，不添加特定格式参数
                    break;
            }
            generatedUrlInput.value = finalUrl;
            // 重置复制按钮状态
            copyUrlBtn.textContent = '复制';
            copyUrlBtn.classList.remove('copied');
            copyUrlBtn.disabled = false;
        }

        formatSelect.addEventListener('change', updateGeneratedUrl);

        copyUrlBtn.addEventListener('click', () => {
            const urlToCopy = generatedUrlInput.value;
            if (!urlToCopy) return; // 如果没有 URL，则不执行任何操作

            navigator.clipboard.writeText(urlToCopy).then(() => {
                // 复制成功反馈
                copyUrlBtn.textContent = '已复制!';
                copyUrlBtn.classList.add('copied');
                copyUrlBtn.disabled = true;
                // 1.5 秒后恢复按钮状态
                setTimeout(() => {
                    copyUrlBtn.textContent = '复制';
                    copyUrlBtn.classList.remove('copied');
                    copyUrlBtn.disabled = false;
                }, 1500);
            }).catch(err => {
                console.error('复制失败:', err);
                // 可以选择给用户一个错误提示，例如 alert('复制失败，请手动复制。');
                copyUrlBtn.textContent = '复制失败';
                 setTimeout(() => {
                    copyUrlBtn.textContent = '复制';
                 }, 2000);
            });
        });

        // 初始化时生成一次链接
        updateGeneratedUrl();
	</script>
</body>
</html>`;

	return new Response(html, {
		headers: { 'Content-Type': 'text/html; charset=UTF-8' },
	});
}

/**
 * 根据 User-Agent 和查询参数确定所需的输出格式。
 * 默认为 Base64。
 * @param {string} userAgent 小写的 User-Agent 字符串。
 * @param {URL} url 请求的 URL 对象。
 * @returns {string} 确定的输出格式 (例如, 'clash', 'base64')。
 */
function determineOutputFormat(userAgent, url) {
	// 首先检查查询参数 (覆盖 User-Agent)
	if (url.searchParams.has('b64') || url.searchParams.has('base64')) return FORMAT_BASE64;
	if (url.searchParams.has('clash')) return FORMAT_CLASH;
	if (url.searchParams.has('sb') || url.searchParams.has('singbox')) return FORMAT_SINGBOX;
	if (url.searchParams.has('surge')) return FORMAT_SURGE;
	if (url.searchParams.has('quanx')) return FORMAT_QUANX;
	if (url.searchParams.has('loon')) return FORMAT_LOON;

	// 回退到 User-Agent 检测
	// 忽略 subconverter 自身的 UA 以避免在获取组合列表时产生循环
	if (userAgent.includes('subconverter')) return FORMAT_BASE64;

	// 客户端检测
	if (userAgent.includes('clash')) return FORMAT_CLASH;
	if (userAgent.includes('stash')) return FORMAT_CLASH; // Stash for iOS uses Clash core
	if (userAgent.includes('meta')) return FORMAT_CLASH; // Clash Meta core
	if (userAgent.includes('sing-box') || userAgent.includes('singbox')) return FORMAT_SINGBOX;
	if (userAgent.includes('surge')) return FORMAT_SURGE;
	if (userAgent.includes('quantumult%20x') || userAgent.includes('quantumult x')) return FORMAT_QUANX; // 处理编码/解码后的 UA
	if (userAgent.includes('loon')) return FORMAT_LOON;
	if (userAgent.includes('shadowrocket')) return FORMAT_BASE64; // Shadowrocket 通常使用 base64
    if (userAgent.includes('nekobox') || userAgent.includes('nekoray')) return FORMAT_BASE64; // NekoBox/NekoRay 默认需要 base64
    if (userAgent.includes('v2rayn') || userAgent.includes('v2rayng')) return FORMAT_BASE64; // V2RayN/NG 需要 base64

    // 为常见的命令行工具或简单 fetcher 添加检测
	if (userAgent.includes('curl') || userAgent.includes('wget') || userAgent === '' || userAgent.includes('okhttp')) return FORMAT_BASE64;
    // 特殊标记，例如来自其他脚本的请求
    if (userAgent.includes('cf-workers-sub')) return FORMAT_BASE64;

    // 对未请求编辑器的未知或类似浏览器的 UA 的默认设置
	// 浏览器访问（非编辑器）默认给 base64，因为无法确定用户意图
	// if (userAgent.includes('mozilla') || userAgent.includes('chrome') || userAgent.includes('safari') || userAgent.includes('edge') || userAgent.includes('firefox')) return FORMAT_BASE64;

	// 如果未检测到特定客户端，则使用默认格式
	return FORMAT_BASE64;
}

/**
 * 确定在获取订阅内容时附加到 User-Agent 的后缀。
 * 如果需要，这有助于向订阅源识别请求客户端类型。
 * @param {URL} url 原始请求的 URL 对象。
 * @returns {string} User-Agent 后缀 (例如, 'clash', 'singbox')。默认为 'v2rayn'。
 */
function getFetchUserAgentSuffix(url) {
    if (url.searchParams.has('clash')) return 'clash';
    if (url.searchParams.has('sb') || url.searchParams.has('singbox')) return 'singbox';
    if (url.searchParams.has('surge')) return 'surge';
    if (url.searchParams.has('quanx')) return 'Quantumult%20X'; // UA 中使用编码形式
    if (url.searchParams.has('loon')) return 'Loon';
    // 如果没有通过查询参数请求特定格式，则使用默认后缀
    return 'v2rayn';
}