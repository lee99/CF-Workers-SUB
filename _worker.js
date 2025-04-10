// 部署完成后在网址后面加上这个，获取自建节点和机场聚合节点，/?token=auto或/auto或

let mytoken = 'auto';
let guestToken = ''; //可以随便取，或者uuid生成，https://1024tools.com/uuid
let FileName = 'CF-Workers-SUB';
let SUBUpdateTime = 6; //自定义订阅更新时间，单位小时
let total = 99;//TB
let timestamp = 4102329600000;//2099-12-31

//节点链接 + 订阅链接
let MainData = `
https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray
https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt
https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt
https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2
https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/airport_sub_merge.txt
https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/sub_merge.txt
https://raw.githubusercontent.com/Pawdroid/Free-servers/refs/heads/main/sub
`

let urls = [];
let subConverter = "SUBAPI.cmliussss.net"; //在线订阅转换后端，目前使用CM的订阅转换功能。支持自建psub 可自行搭建https://github.com/bulianglin/psub
let subConfig = "https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/config/ACL4SSR_Online_MultiCountry.ini"; //订阅配置文件
let subProtocol = 'https';

export default {
	async fetch(request, env) {
		const userAgentHeader = request.headers.get('User-Agent');
		const userAgent = userAgentHeader ? userAgentHeader.toLowerCase() : "null";
		const url = new URL(request.url);
		const token = url.searchParams.get('token');
		mytoken = env.TOKEN || mytoken;
		subConverter = env.SUBAPI || subConverter;
		if (subConverter.includes("http://")) {
			subConverter = subConverter.split("//")[1];
			subProtocol = 'http';
		} else {
			subConverter = subConverter.split("//")[1] || subConverter;
		}
		subConfig = env.SUBCONFIG || subConfig;
		FileName = env.SUBNAME || FileName;

		const currentDate = new Date();
		currentDate.setHours(0, 0, 0, 0);
		const timeTemp = Math.ceil(currentDate.getTime() / 1000);
		const fakeToken = await MD5MD5(`${mytoken}${timeTemp}`);
		guestToken = env.GUESTTOKEN || env.GUEST || guestToken;
		if (!guestToken) guestToken = await MD5MD5(mytoken);
		const 访客订阅 = guestToken;
		//console.log(`${fakeUserID}\n${fakeHostName}`); // 打印fakeID

		let UD = Math.floor(((timestamp - Date.now()) / timestamp * total * 1099511627776) / 2);
		total = total * 1099511627776;
		let expire = Math.floor(timestamp / 1000);
		SUBUpdateTime = env.SUBUPTIME || SUBUpdateTime;

		if (!([mytoken, fakeToken, 访客订阅].includes(token) || url.pathname == ("/" + mytoken) || url.pathname.includes("/" + mytoken + "?"))) {
			if (env.URL302) return Response.redirect(env.URL302, 302);
			else if (env.URL) return await proxyURL(env.URL, url);
			else return new Response(null, { status: 403 });
		} else {
			if (env.KV) {
				await 迁移地址列表(env, 'LINK.txt');
				if (userAgent.includes('mozilla') && !url.search) {
					return await KV(request, env, 'LINK.txt', 访客订阅);
				} else {
					MainData = await env.KV.get('LINK.txt') || MainData;
				}
			} else {
				MainData = env.LINK || MainData;
				if (env.LINKSUB) urls = await ADD(env.LINKSUB);
			}
			let 重新汇总所有链接 = await ADD(MainData + '\n' + urls.join('\n'));
			let 自建节点 = "";
			let 订阅链接 = "";
			for (let x of 重新汇总所有链接) {
				if (x.toLowerCase().startsWith('http')) {
					订阅链接 += x + '\n';
				} else {
					自建节点 += x + '\n';
				}
			}
			MainData = 自建节点;
			urls = await ADD(订阅链接);

			let 订阅格式 = 'base64';
			if (userAgent.includes('null') || userAgent.includes('subconverter') || userAgent.includes('nekobox') || userAgent.includes(('CF-Workers-SUB').toLowerCase())) {
				订阅格式 = 'base64';
			} else if (userAgent.includes('clash') || (url.searchParams.has('clash') && !userAgent.includes('subconverter'))) {
				订阅格式 = 'clash';
			} else if (userAgent.includes('sing-box') || userAgent.includes('singbox') || ((url.searchParams.has('sb') || url.searchParams.has('singbox')) && !userAgent.includes('subconverter'))) {
				订阅格式 = 'singbox';
			} else if (userAgent.includes('surge') || (url.searchParams.has('surge') && !userAgent.includes('subconverter'))) {
				订阅格式 = 'surge';
			} else if (userAgent.includes('quantumult%20x') || (url.searchParams.has('quanx') && !userAgent.includes('subconverter'))) {
				订阅格式 = 'quanx';
			} else if (userAgent.includes('loon') || (url.searchParams.has('loon') && !userAgent.includes('subconverter'))) {
				订阅格式 = 'loon';
			}

			let subConverterUrl;
			let 订阅转换URL = `${url.origin}/${await MD5MD5(fakeToken)}?token=${fakeToken}`;
			//console.log(订阅转换URL);
			let req_data = MainData;

			let 追加UA = 'v2rayn';
			if (url.searchParams.has('b64') || url.searchParams.has('base64')) 订阅格式 = 'base64';
			else if (url.searchParams.has('clash')) 追加UA = 'clash';
			else if (url.searchParams.has('singbox')) 追加UA = 'singbox';
			else if (url.searchParams.has('surge')) 追加UA = 'surge';
			else if (url.searchParams.has('quanx')) 追加UA = 'Quantumult%20X';
			else if (url.searchParams.has('loon')) 追加UA = 'Loon';

			const 请求订阅响应内容 = await getSUB(urls, request, 追加UA, userAgentHeader);
			console.log(请求订阅响应内容);
			req_data += 请求订阅响应内容[0].join('\n');
			订阅转换URL += "|" + 请求订阅响应内容[1];

			if (env.WARP) 订阅转换URL += "|" + (await ADD(env.WARP)).join("|");
			//修复中文错误
			const utf8Encoder = new TextEncoder();
			const encodedData = utf8Encoder.encode(req_data);
			//const text = String.fromCharCode.apply(null, encodedData);
			const utf8Decoder = new TextDecoder();
			const text = utf8Decoder.decode(encodedData);

			//去重
			const uniqueLines = new Set(text.split('\n'));
			const result = [...uniqueLines].join('\n');
			//console.log(result);

			let base64Data;
			try {
				base64Data = btoa(result);
			} catch (e) {
				function encodeBase64(data) {
					const binary = new TextEncoder().encode(data);
					let base64 = '';
					const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

					for (let i = 0; i < binary.length; i += 3) {
						const byte1 = binary[i];
						const byte2 = binary[i + 1] || 0;
						const byte3 = binary[i + 2] || 0;

						base64 += chars[byte1 >> 2];
						base64 += chars[((byte1 & 3) << 4) | (byte2 >> 4)];
						base64 += chars[((byte2 & 15) << 2) | (byte3 >> 6)];
						base64 += chars[byte3 & 63];
					}

					const padding = 3 - (binary.length % 3 || 3);
					return base64.slice(0, base64.length - padding) + '=='.slice(0, padding);
				}

				base64Data = encodeBase64(result.replace(/\u0026/g, '&'))
			}

			if (订阅格式 == 'base64' || token == fakeToken) {
				return new Response(base64Data, {
					headers: {
						"content-type": "text/plain; charset=utf-8",
						"Profile-Update-Interval": `${SUBUpdateTime}`,
						//"Subscription-Userinfo": `upload=${UD}; download=${UD}; total=${total}; expire=${expire}`,
					}
				});
			} else if (订阅格式 == 'clash') {
				subConverterUrl = `${subProtocol}://${subConverter}/sub?target=clash&url=${encodeURIComponent(订阅转换URL)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
			} else if (订阅格式 == 'singbox') {
				subConverterUrl = `${subProtocol}://${subConverter}/sub?target=singbox&url=${encodeURIComponent(订阅转换URL)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
			} else if (订阅格式 == 'surge') {
				subConverterUrl = `${subProtocol}://${subConverter}/sub?target=surge&ver=4&url=${encodeURIComponent(订阅转换URL)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
			} else if (订阅格式 == 'quanx') {
				subConverterUrl = `${subProtocol}://${subConverter}/sub?target=quanx&url=${encodeURIComponent(订阅转换URL)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&udp=true`;
			} else if (订阅格式 == 'loon') {
				subConverterUrl = `${subProtocol}://${subConverter}/sub?target=loon&url=${encodeURIComponent(订阅转换URL)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false`;
			}
			//console.log(订阅转换URL);
			try {
				const subConverterResponse = await fetch(subConverterUrl);

				if (!subConverterResponse.ok) {
					return new Response(base64Data, {
						headers: {
							"content-type": "text/plain; charset=utf-8",
							"Profile-Update-Interval": `${SUBUpdateTime}`,
							//"Subscription-Userinfo": `upload=${UD}; download=${UD}; total=${total}; expire=${expire}`,
						}
					});
					//throw new Error(`Error fetching subConverterUrl: ${subConverterResponse.status} ${subConverterResponse.statusText}`);
				}
				let subConverterContent = await subConverterResponse.text();
				if (订阅格式 == 'clash') subConverterContent = await clashFix(subConverterContent);
				return new Response(subConverterContent, {
					headers: {
						"Content-Disposition": `attachment; filename*=utf-8''${encodeURIComponent(FileName)}`,
						"content-type": "text/plain; charset=utf-8",
						"Profile-Update-Interval": `${SUBUpdateTime}`,
						//"Subscription-Userinfo": `upload=${UD}; download=${UD}; total=${total}; expire=${expire}`,

					},
				});
			} catch (error) {
				return new Response(base64Data, {
					headers: {
						"content-type": "text/plain; charset=utf-8",
						"Profile-Update-Interval": `${SUBUpdateTime}`,
						//"Subscription-Userinfo": `upload=${UD}; download=${UD}; total=${total}; expire=${expire}`,
					}
				});
			}
		}
	}
};

async function ADD(envadd) {
	var addtext = envadd.replace(/[	"'|\r\n]+/g, ',').replace(/,+/g, ',');	// 将空格、双引号、单引号和换行符替换为逗号
	//console.log(addtext);
	if (addtext.charAt(0) == ',') addtext = addtext.slice(1);
	if (addtext.charAt(addtext.length - 1) == ',') addtext = addtext.slice(0, addtext.length - 1);
	const add = addtext.split(',');
	//console.log(add);
	return add;
}

async function nginx() {
	const text = `
	<!DOCTYPE html>
	<html>
	<head>
	<title>Welcome to nginx!</title>
	<style>
		body {
			width: 35em;
			margin: 0 auto;
			font-family: Tahoma, Verdana, Arial, sans-serif;
		}
	</style>
	</head>
	<body>
	<h1>Welcome to nginx!</h1>
	<p>If you see this page, the nginx web server is successfully installed and
	working. Further configuration is required.</p>
	
	<p>For online documentation and support please refer to
	<a href="http://nginx.org/">nginx.org</a>.<br/>
	Commercial support is available at
	<a href="http://nginx.com/">nginx.com</a>.</p>
	
	<p><em>Thank you for using nginx.</em></p>
	</body>
	</html>
	`
	return text;
}

function base64Decode(str) {
	const bytes = new Uint8Array(atob(str).split('').map(c => c.charCodeAt(0)));
	const decoder = new TextDecoder('utf-8');
	return decoder.decode(bytes);
}

async function MD5MD5(text) {
	const encoder = new TextEncoder();

	const firstPass = await crypto.subtle.digest('MD5', encoder.encode(text));
	const firstPassArray = Array.from(new Uint8Array(firstPass));
	const firstHex = firstPassArray.map(b => b.toString(16).padStart(2, '0')).join('');

	const secondPass = await crypto.subtle.digest('MD5', encoder.encode(firstHex.slice(7, 27)));
	const secondPassArray = Array.from(new Uint8Array(secondPass));
	const secondHex = secondPassArray.map(b => b.toString(16).padStart(2, '0')).join('');

	return secondHex.toLowerCase();
}

function clashFix(content) {
	if (content.includes('wireguard') && !content.includes('remote-dns-resolve')) {
		let lines;
		if (content.includes('\r\n')) {
			lines = content.split('\r\n');
		} else {
			lines = content.split('\n');
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

		content = result;
	}
	return content;
}

async function proxyURL(proxyURL, url) {
	const URLs = await ADD(proxyURL);
	const fullURL = URLs[Math.floor(Math.random() * URLs.length)];

	// 解析目标 URL
	let parsedURL = new URL(fullURL);
	console.log(parsedURL);
	// 提取并可能修改 URL 组件
	let URLProtocol = parsedURL.protocol.slice(0, -1) || 'https';
	let URLHostname = parsedURL.hostname;
	let URLPathname = parsedURL.pathname;
	let URLSearch = parsedURL.search;

	// 处理 pathname
	if (URLPathname.charAt(URLPathname.length - 1) == '/') {
		URLPathname = URLPathname.slice(0, -1);
	}
	URLPathname += url.pathname;

	// 构建新的 URL
	let newURL = `${URLProtocol}://${URLHostname}${URLPathname}${URLSearch}`;

	// 反向代理请求
	let response = await fetch(newURL);

	// 创建新的响应
	let newResponse = new Response(response.body, {
		status: response.status,
		statusText: response.statusText,
		headers: response.headers
	});

	// 添加自定义头部，包含 URL 信息
	//newResponse.headers.set('X-Proxied-By', 'Cloudflare Worker');
	//newResponse.headers.set('X-Original-URL', fullURL);
	newResponse.headers.set('X-New-URL', newURL);

	return newResponse;
}

async function getSUB(api, request, 追加UA, userAgentHeader) {
	if (!api || api.length === 0) {
		return [];
	} else api = [...new Set(api)]; // 去重
	let newapi = "";
	let 订阅转换URLs = "";
	let 异常订阅 = "";
	const controller = new AbortController(); // 创建一个AbortController实例，用于取消请求
	const timeout = setTimeout(() => {
		controller.abort(); // 2秒后取消所有请求
	}, 2000);

	try {
		// 使用Promise.allSettled等待所有API请求完成，无论成功或失败
		const responses = await Promise.allSettled(api.map(apiUrl => getUrl(request, apiUrl, 追加UA, userAgentHeader).then(response => response.ok ? response.text() : Promise.reject(response))));

		// 遍历所有响应
		const modifiedResponses = responses.map((response, index) => {
			// 检查是否请求成功
			if (response.status === 'rejected') {
				const reason = response.reason;
				if (reason && reason.name === 'AbortError') {
					return {
						status: '超时',
						value: null,
						apiUrl: api[index] // 将原始的apiUrl添加到返回对象中
					};
				}
				console.error(`请求失败: ${api[index]}, 错误信息: ${reason.status} ${reason.statusText}`);
				return {
					status: '请求失败',
					value: null,
					apiUrl: api[index] // 将原始的apiUrl添加到返回对象中
				};
			}
			return {
				status: response.status,
				value: response.value,
				apiUrl: api[index] // 将原始的apiUrl添加到返回对象中
			};
		});

		console.log(modifiedResponses); // 输出修改后的响应数组

		for (const response of modifiedResponses) {
			// 检查响应状态是否为'fulfilled'
			if (response.status === 'fulfilled') {
				const content = await response.value || 'null'; // 获取响应的内容
				if (content.includes('proxies:')) {
					//console.log('Clash订阅: ' + response.apiUrl);
					订阅转换URLs += "|" + response.apiUrl; // Clash 配置
				} else if (content.includes('outbounds"') && content.includes('inbounds"')) {
					//console.log('Singbox订阅: ' + response.apiUrl);
					订阅转换URLs += "|" + response.apiUrl; // Singbox 配置
				} else if (content.includes('://')) {
					//console.log('明文订阅: ' + response.apiUrl);
					newapi += content + '\n'; // 追加内容
				} else if (isValidBase64(content)) {
					//console.log('Base64订阅: ' + response.apiUrl);
					newapi += base64Decode(content) + '\n'; // 解码并追加内容
				} else {
					const 异常订阅LINK = `trojan://CMLiussss@127.0.0.1:8888?security=tls&allowInsecure=1&type=tcp&headerType=none#%E5%BC%82%E5%B8%B8%E8%AE%A2%E9%98%85%20${response.apiUrl.split('://')[1].split('/')[0]}`;
					console.log('异常订阅: ' + 异常订阅LINK);
					异常订阅 += `${异常订阅LINK}\n`;
				}
			}
		}
	} catch (error) {
		console.error(error); // 捕获并输出错误信息
	} finally {
		clearTimeout(timeout); // 清除定时器
	}

	const 订阅内容 = await ADD(newapi + 异常订阅); // 将处理后的内容转换为数组
	// 返回处理后的结果
	return [订阅内容, 订阅转换URLs];
}

async function getUrl(request, targetUrl, 追加UA, userAgentHeader) {
	// 设置自定义 User-Agent
	const newHeaders = new Headers(request.headers);
	newHeaders.set("User-Agent", `${atob('djJyYXlOLzYuNDU=')} cmliu/CF-Workers-SUB ${追加UA}(${userAgentHeader})`);

	// 构建新的请求对象
	const modifiedRequest = new Request(targetUrl, {
		method: request.method,
		headers: newHeaders,
		body: request.method === "GET" ? null : request.body,
		redirect: "follow",
		cf: {
			// 忽略SSL证书验证
			insecureSkipVerify: true,
			// 允许自签名证书
			allowUntrusted: true,
			// 禁用证书验证
			validateCertificate: false
		}
	});

	// 输出请求的详细信息
	console.log(`请求URL: ${targetUrl}`);
	console.log(`请求头: ${JSON.stringify([...newHeaders])}`);
	console.log(`请求方法: ${request.method}`);
	console.log(`请求体: ${request.method === "GET" ? null : request.body}`);

	// 发送请求并返回响应
	return fetch(modifiedRequest);
}

function isValidBase64(str) {
	// 先移除所有空白字符(空格、换行、回车等)
	const cleanStr = str.replace(/\s/g, '');
	const base64Regex = /^[A-Za-z0-9+/=]+$/;
	return base64Regex.test(cleanStr);
}

async function 迁移地址列表(env, txt = 'ADD.txt') {
	const 旧数据 = await env.KV.get(`/${txt}`);
	const 新数据 = await env.KV.get(txt);

	if (旧数据 && !新数据) {
		// 写入新位置
		await env.KV.put(txt, 旧数据);
		// 删除旧数据
		await env.KV.delete(`/${txt}`);
		return true;
	}
	return false;
}

async function KV(request, env, txt = 'ADD.txt', guest) {
	const url = new URL(request.url);
	let message = '';
	let messageType = 'info'; // success, error, info

	try {
		// POST请求处理
		if (request.method === "POST") {
			if (!env.KV) return new Response("未绑定KV空间", { status: 400 });
			try {
				// 使用表单数据处理
				const contentType = request.headers.get('content-type');
				if (contentType && contentType.includes('application/x-www-form-urlencoded')) {
					const formData = await request.formData();
					const content = formData.get('content') || '';
					await env.KV.put(txt, content.trim());
					message = "列表已成功更新！";
					messageType = 'success';
				} else {
					// 如果不是表单，尝试作为纯文本处理 (兼容旧逻辑，但优先表单)
					const content = await request.text();
					await env.KV.put(txt, content.trim());
					message = "列表已成功更新 (纯文本模式)！";
					messageType = 'success';
				}
			} catch (error) {
				console.error('保存KV时发生错误:', error);
				message = "保存失败: " + error.message;
				messageType = 'error';
			}
		}

		// GET请求部分
		let content = '';
		let hasKV = !!env.KV;

		if (hasKV) {
			try {
				content = await env.KV.get(txt) || '';
			} catch (error) {
				console.error('读取KV时发生错误:', error);
				content = '读取数据时发生错误: ' + error.message;
				messageType = 'error'; // 也将读取错误标记为错误信息
			}
		}

		// 基础 URL
		const baseUrl = `https://${url.hostname}`;
		const adminBase = `${baseUrl}/${mytoken}`;
		// 访客路径调整为 /sub?token=...
		const guestBase = `${baseUrl}/sub?token=${guest}`; 

		// 定义订阅链接格式
		const formats = {
			auto: { name: "自适应订阅", param: "" },
			base64: { name: "Base64 订阅", param: "&b64" }, // 统一使用 & 连接符
			clash: { name: "Clash 订阅", param: "&clash" },
			singbox: { name: "Sing-Box 订阅", param: "&sb" },
			surge: { name: "Surge 订阅", param: "&surge" },
			quanx: { name: "Quantumult X 订阅", param: "&quanx" },
			loon: { name: "Loon 订阅", param: "&loon" },
		};

		// 生成链接 HTML 的辅助函数
		function generateLinksHtml(base, isGuest = false) {
			let linksHtml = '';
			for (const key in formats) {
				const format = formats[key];
				// 对 guest 链接，第一个参数是 ?token=... ，后续用 &
				// 对 admin 链接，第一个参数是 ? 或直接 /token 后跟 ?
				let linkUrl;
				if (isGuest) {
					linkUrl = base + format.param; // guestBase 已经包含 ?token=
				} else {
					// adminBase 是 /token, 第一个参数用 ?
					linkUrl = base + (format.param ? `?${format.param.substring(1)}` : ''); 
				}

				linksHtml += `
					<div class="link-item">
						<span class="link-name">${format.name}:</span>
						<div class="link-input-group">
							<input type="text" value="${linkUrl}" readonly>
							<button type="button" class="copy-btn" data-clipboard-text="${linkUrl}">复制</button>
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
	<title>${FileName} - 订阅管理</title>
	<style>
		:root {
			--primary-color: #007bff;
			--secondary-color: #6c757d;
			--bg-color: #f8f9fa;
			--card-bg: #ffffff;
			--text-color: #212529;
			--border-color: #dee2e6;
			--link-color: #0056b3;
			--success-bg: #d1e7dd;
			--success-text: #0f5132;
			--success-border: #badbcc;
			--error-bg: #f8d7da;
			--error-text: #842029;
			--error-border: #f5c2c7;
			--info-bg: #cff4fc;
			--info-text: #055160;
			--info-border: #b6effb;
		}
		body {
			font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol";
			margin: 0;
			background-color: var(--bg-color);
			color: var(--text-color);
			line-height: 1.6;
		}
		.header {
			background-color: #343a40;
			color: white;
			padding: 1rem 1.5rem;
			margin-bottom: 2rem;
			box-shadow: 0 2px 4px rgba(0,0,0,0.1);
		}
		.header h1 {
			margin: 0;
			font-size: 1.6rem;
			text-align: center;
		}
		.container {
			max-width: 960px;
			margin: 0 auto 2rem auto;
			padding: 0 1rem;
		}
		.card {
			background-color: var(--card-bg);
			border-radius: 8px;
			box-shadow: 0 4px 8px rgba(0, 0, 0, 0.08);
			margin-bottom: 2rem;
			overflow: hidden; /* Contain borders */
		}
		.card-header {
			padding: 1rem 1.5rem;
			border-bottom: 1px solid var(--border-color);
			background-color: #f1f3f5; /* Slightly different header bg */
		}
		.card-header h2 {
			margin: 0;
			font-size: 1.3rem;
			color: #495057;
		}
		.card-body {
			padding: 1.5rem;
		}
		/* Tabs */
		.tab-nav {
			display: flex;
			border-bottom: 1px solid var(--border-color);
			margin-bottom: 1.5rem;
		}
		.tab-button {
			padding: 0.8rem 1.2rem;
			cursor: pointer;
			border: none;
			background-color: transparent;
			font-size: 1rem;
			color: var(--secondary-color);
			border-bottom: 3px solid transparent; /* Placeholder for active state */
			margin-bottom: -1px; /* Overlap border */
			transition: color 0.2s ease, border-color 0.2s ease;
		}
		.tab-button:hover {
			color: var(--text-color);
		}
		.tab-button.active {
			color: var(--primary-color);
			border-bottom-color: var(--primary-color);
			font-weight: 500;
		}
		.tab-content {
			display: none;
		}
		.tab-content.active {
			display: block;
		}
		/* Links Display */
		.link-item {
			margin-bottom: 1rem;
			padding-bottom: 1rem;
			border-bottom: 1px dashed #e0e0e0;
		}
		.link-item:last-child {
			margin-bottom: 0;
			padding-bottom: 0;
			border-bottom: none;
		}
		.link-name {
			display: block;
			font-weight: 500;
			margin-bottom: 0.4rem;
			color: #555;
		}
		.link-input-group {
			display: flex;
			align-items: center;
			gap: 0.5rem;
		}
		.link-input-group input[type="text"] {
			flex-grow: 1;
			padding: 0.5em 0.8em;
			border: 1px solid #ced4da;
			border-radius: 4px;
			font-size: 0.95em;
			background-color: #e9ecef; /* Readonly background */
		}
		.copy-btn {
			padding: 0.4em 0.9em;
			font-size: 0.9em;
			background-color: var(--secondary-color);
			color: white;
			border: none;
			border-radius: 4px;
			cursor: pointer;
			transition: background-color 0.2s ease;
			white-space: nowrap; /* Prevent button text wrapping */
		}
		.copy-btn:hover {
			background-color: #5a6268;
		}
		.copy-btn.copied {
			background-color: #28a745; /* Green for copied */
			cursor: default;
		}

		/* Editor */
		label {
			display: block;
			margin-bottom: 0.5rem;
			font-weight: 500;
		}
		textarea {
			width: 100%;
			min-height: 300px;
			margin-bottom: 1rem;
			border: 1px solid var(--border-color);
			border-radius: 4px;
			padding: 0.75em;
			font-size: 14px;
			line-height: 1.5;
			box-sizing: border-box;
			resize: vertical;
		}
		.save-btn {
			padding: 0.75em 1.5em;
			background-color: var(--primary-color);
			color: white;
			border: none;
			border-radius: 4px;
			cursor: pointer;
			font-size: 1em;
			transition: background-color 0.2s ease;
		}
		.save-btn:hover {
			background-color: #0056b3;
		}

		/* Messages */
		.message {
			padding: 1rem 1.25rem;
			margin-bottom: 1.5rem;
			border: 1px solid transparent;
			border-radius: 0.375rem;
			font-size: 0.95rem;
		}
		.message.success { color: var(--success-text); background-color: var(--success-bg); border-color: var(--success-border); }
		.message.error { color: var(--error-text); background-color: var(--error-bg); border-color: var(--error-border); }
		.message.info { color: var(--info-text); background-color: var(--info-bg); border-color: var(--info-border); }

		/* Footer */
		footer {
			text-align: center;
			margin-top: 3rem;
			padding: 1.5rem 1rem;
			font-size: 0.9em;
			color: #6c757d;
			border-top: 1px solid var(--border-color);
		}
	</style>
</head>
<body>
	<header class="header">
		<h1>${FileName} - 订阅管理</h1>
	</header>

	<div class="container">
		${message ? `<div class="message ${messageType}">${content || message}</div>` : ''} 

		<!-- 订阅链接展示卡片 -->
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
					${generateLinksHtml(adminBase, false)}
				</div>

				<div id="guest-links" class="tab-content">
					${guest ? generateLinksHtml(guestBase, true) : '<p>未配置访客令牌 (GUESTTOKEN 或 GUEST 环境变量)。</p>'}
				</div>
			</div>
		</div>

		<!-- KV 编辑器卡片 -->
		${hasKV ? `
		<div class="card">
			<div class="card-header">
				<h2>编辑订阅源 (${txt})</h2>
			</div>
			<div class="card-body">
				<form method="POST" action="">
					<label for="content">源列表 (每行一个链接或节点信息):</label>
					<textarea id="content" name="content" placeholder="在此输入订阅链接或节点信息，每行一个...\n例如:\nhttps://example.com/mysub\nvmess://...\ntrojan://...">${content}</textarea>
					<button type="submit" class="save-btn">保存更改</button>
				</form>
			</div>
		</div>
		` : `
		<div class="card">
			<div class="card-body">
				<p><strong>注意:</strong> 未绑定名为 <strong>KV</strong> 的 KV 命名空间，无法在线编辑订阅源列表。</p>
				<p>当前使用的是环境变量或代码内置的默认源。</p>
			</div>
		</div>
		`}
	</div>

	<footer>
		Powered by Cloudflare Workers
	</footer>

	<script>
		// Tab 切换逻辑
		const tabButtons = document.querySelectorAll('.tab-button');
		const tabContents = document.querySelectorAll('.tab-content');

		tabButtons.forEach(button => {
			button.addEventListener('click', () => {
				// 移除所有按钮的 active 类
				tabButtons.forEach(btn => btn.classList.remove('active'));
				// 为点击的按钮添加 active 类
				button.classList.add('active');

				// 隐藏所有内容区域
				tabContents.forEach(content => content.classList.remove('active'));
				// 显示目标内容区域
				const targetTab = button.getAttribute('data-tab');
				document.getElementById(targetTab).classList.add('active');
			});
		});

		// 复制按钮逻辑
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
					// 可以添加更友好的错误提示
					button.textContent = '失败';
					 setTimeout(() => {
						button.textContent = '复制';
					 }, 2000);
				});
			});
		});
	</script>
</body>
</html>
		`;

		return new Response(html, {
			headers: { "Content-Type": "text/html;charset=utf-8" }
		});
	} catch (error) {
		console.error('处理请求时发生错误:', error);
		return new Response("服务器错误: " + error.message, {
			status: 500,
			headers: { "Content-Type": "text/plain;charset=utf-8" }
		});
	}
}
