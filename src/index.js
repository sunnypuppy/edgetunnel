import { connect } from 'cloudflare:sockets';
import { createHash } from 'node:crypto';

let userID = 'd342d11e-d424-4583-b36e-524ab1f0afa4';
let socks5Proxy = ''; // username:passwd@127.0.0.1:8080

export default {
	async fetch(request, env, ctx) {
		userID = env.UUID || userID;
		socks5Proxy = env.SOCKS5_PROXY || socks5Proxy;

		if (request.headers.get('Upgrade') === 'websocket') {
			return handlerWebSocketRequest(request);
		}
		return handlerHTTPRequest(request);
	},
};

function consoleLog(...args) {
	const now = new Date();
	const timestamp = now.toISOString().replace('T', ' ').split('.')[0] + '.' + now.getMilliseconds().toString().padStart(3, '0');
	console.log(`[${timestamp}]`, ...args);
}

// 1 handlerWebSocketRequest
async function handlerWebSocketRequest(request) {
	// websockt: client <--> server
	const [client, webSocket] = Object.values(new WebSocketPair());
	webSocket.accept();

	// proxysocket: server <--> remote
	let proxySocket = { tcpSocket: null };

	// parse subprotocol
	const subProtocol = parseSubProtocol(request);

	// handler client to server readable stream
	const c2sRStream = c2sRStreamHandler(request, webSocket);
	// handler server to remote writable stream
	const s2rWStream = s2rWStreamHandler(proxySocket, webSocket, subProtocol);
	// pass data by pipe
	c2sRStream.pipeTo(s2rWStream);

	return new Response(null, {
		status: 101,
		webSocket: client,
	});
}

// 1.1 parseSubProtocol
function parseSubProtocol(request) {
	const url = new URL(request.url);
	let subProtocol;
	switch (url.pathname) {
		case '/vless':
			subProtocol = 'vless'
			break;
		case '/trojan':
			subProtocol = 'trojan'
			break;
		default:
			consoleLog(`Unsupported websocket path: ${url.pathname}`);
			throw new Error("Unsupported websocket path");
	}

	return subProtocol;
}

// 1.2 c2sRStreamHandler
function c2sRStreamHandler(request, webSocket) {
	return new ReadableStream({
		start(controller) {
			webSocket.addEventListener('message', event => {
				controller.enqueue(event.data);
			});
			webSocket.addEventListener('close', event => {
				consoleLog(`websocket close event: ${JSON.stringify(event)}`);
			});
			webSocket.addEventListener('error', event => {
				consoleLog(`websocket error event: ${event.message}`);
			});

			// 0-RTT
			const secWebSocketProtocolHeader = request.headers.get('sec-websocket-protocol');
			controller.enqueue(base64ToUint8Array(secWebSocketProtocolHeader));
		},
	});
}

// 1.2.1 base64ToUint8Array
function base64ToUint8Array(base64Url) {
	let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
	while (base64.length % 4 !== 0) {
		base64 += '=';
	}

	const binaryString = atob(base64);
	const len = binaryString.length;
	const bytes = new Uint8Array(len);
	for (let i = 0; i < len; i++) {
		bytes[i] = binaryString.charCodeAt(i);
	}
	return bytes;
}

// 1.3 s2rWStreamHandler
function s2rWStreamHandler(proxySocket, webSocket, subProtocol) {
	return new WritableStream({
		async write(chunk, controller) {
			if (proxySocket.tcpSocket) {
				const writer = proxySocket.tcpSocket.writable.getWriter()
				await writer.write(chunk);
				writer.releaseLock();
				return;
			}

			// parse 0-RTT data from header
			const subProtocolData = parseSubProtocolDataFromHeader(subProtocol, chunk);

			// connect to remote
			handshakeWithRemote(proxySocket, webSocket, subProtocolData);
		}
	});
}

// 1.3.1 parseSubProtocolDataFromHeader
function parseSubProtocolDataFromHeader(protocol, data) {
	switch (protocol) {
		case 'vless':
			const vlessHeader = parseVLESSHeader(data);
			// auth check
			if (vlessHeader.uuid !== userID.replace(/-/g, '')) {
				consoleLog(`VLESS protocol UUID mismatch`);
				throw new Error(`VLESS protocol UUID mismatch`);
			}
			vlessHeader.remoteAddressType = (addressType => {
				switch (addressType) {
					case 0x01:
						return 0x01;
					case 0x02:
						return 0x03;
					case 0x03:
						return 0x04;
					default:
						throw new Error('Unsupported address type');
				}
			})(vlessHeader.remoteAddressType);
			return {
				...vlessHeader,
				responseHeader: new Uint8Array([vlessHeader.version, 0x00])
			};
		case 'trojan':
			const trojanHeader = parseTrojanHeader(data);
			// auth check
			if (trojanHeader.hexSHA224PassWD !== createHash('sha224').update(userID).digest('hex')) {
				consoleLog(`Trojan protocol password mismatch`);
				throw new Error(`Trojan protocol password mismatch`);
			}
			return { ...trojanHeader };
		default:
			consoleLog(`Unknown websocket subprotocol: ${protocol}`);
			throw new Error("Unknown websocket subprotocol");
	}
}

// 1.3.1.1 parseVLESSHeader
// ref: https://xtls.github.io/development/protocols/vless.html
function parseVLESSHeader(data) {
	let offset = 0;

	// Version (1 byte)
	const version = data[offset++];

	// UUID (16 bytes)
	const uuidBytes = data.slice(offset, offset + 16);
	const uuid = [...uuidBytes].map(b => b.toString(16).padStart(2, '0')).join('');
	offset += 16;

	// Addons Length (1 byte)
	const addonsLength = data[offset++];

	// Addons (n bytes)
	const addons = data.slice(offset, offset + addonsLength);
	offset += addonsLength;

	// Command (1 byte)
	const command = data[offset++];

	// Target Port (2 bytes)
	const portBytes = data.slice(offset, offset + 2);
	const remotePort = (portBytes[0] << 8) + portBytes[1];
	offset += 2;

	// Address Type (1 byte)
	let remoteAddressType = data[offset++];

	// Parse the address based on Address Type
	let remoteAddress = '';
	if (remoteAddressType === 0x01) {
		// IPv4 (4 bytes)
		const ipv4Bytes = data.slice(offset, offset + 4);
		remoteAddress = ipv4Bytes.join('.');
		offset += 4;
	} else if (remoteAddressType === 0x02) {
		// Domain Name (1 byte length + domain name)
		const domainLength = data[offset++];
		const domainBytes = data.slice(offset, offset + domainLength);
		remoteAddress = new TextDecoder().decode(domainBytes);
		offset += domainLength;
	} else if (remoteAddressType === 0x03) {
		// IPv6 (16 bytes)
		const ipv6Bytes = data.slice(offset, offset + 16);
		remoteAddress = [...ipv6Bytes].map(b => b.toString(16).padStart(2, '0')).join(':');
		offset += 16;
	}

	// Extract remaining data as payload
	const payload = data.slice(offset);

	return {
		version,
		uuid,
		command,
		remotePort,
		remoteAddressType,
		remoteAddress,
		payload
	};
}

// 1.3.1.2 parseTrojanHeader
// ref: https://trojan-gfw.github.io/trojan/protocol
function parseTrojanHeader(data) {
	let offset = 0;

	// hex(SHA224(password)) (56 bytes)
	const hexSHA224PassWD = new TextDecoder().decode(data.slice(offset, offset + 56));
	offset += 56;

	// CRLF (2 bytes)
	let CR = data[offset++];
	let LF = data[offset++];

	// Trojan Request
	// CMD (1 byte)
	const command = data[offset++];
	// ATYP (1 byte)
	let remoteAddressType = data[offset++];
	// DST.ADDR (n bytes)
	let remoteAddress = '';
	if (remoteAddressType === 0x01) {
		// IPv4 (4 bytes)
		const ipv4Bytes = data.slice(offset, offset + 4);
		remoteAddress = ipv4Bytes.join('.');
		offset += 4;
	} else if (remoteAddressType === 0x03) {
		// Domain Name (1 byte length + domain name)
		const domainLength = data[offset++];
		const domainBytes = data.slice(offset, offset + domainLength);
		remoteAddress = new TextDecoder().decode(domainBytes);
		offset += domainLength;
	} else if (remoteAddressType === 0x04) {
		// IPv6 (16 bytes)
		const ipv6Bytes = data.slice(offset, offset + 16);
		remoteAddress = [...ipv6Bytes].map(b => b.toString(16).padStart(2, '0')).join(':');
		offset += 16;
	}
	// DST.PORT (2 bytes)
	const portBytes = data.slice(offset, offset + 2);
	const remotePort = (portBytes[0] << 8) + portBytes[1];
	offset += 2;

	// CRLF
	CR = data[offset++];
	LF = data[offset++];

	// Payload
	const payload = data.slice(offset);

	return {
		hexSHA224PassWD,
		command,
		remoteAddressType,
		remoteAddress,
		remotePort,
		payload
	};
}

// 1.3.2 handshakeWithRemote
async function handshakeWithRemote(proxySocket, webSocket, subProtocolData, useProxy = false) {
	let needRetryByProxy = false;

	// 1.connect
	if (useProxy) {
		if (socks5Proxy) {
			consoleLog(`connect to ${subProtocolData.remoteAddress}:${subProtocolData.remotePort} by socks5 proxy`);
			proxySocket.tcpSocket = await connectBySocks5(subProtocolData.remoteAddressType, subProtocolData.remoteAddress, subProtocolData.remotePort)
		} else {
			throw new Error("No available proxy config");
		}
	} else {
		consoleLog(`connect to ${subProtocolData.remoteAddress}:${subProtocolData.remotePort}`);
		proxySocket.tcpSocket = connect({ hostname: subProtocolData.remoteAddress, port: subProtocolData.remotePort });
	}

	// 2.process 0-RTT data
	consoleLog(`0-rtt data write start: ${subProtocolData.payload.byteLength}`);
	const writer = proxySocket.tcpSocket.writable.getWriter();
	try {
		await Promise.race([
			writer.write(subProtocolData.payload),
			new Promise((_, reject) => setTimeout(() => reject(new Error("Write operation timed out")), 3000))
		]);
	} catch (error) {
		consoleLog(`0-rtt data write error: ${error.message}`);
		needRetryByProxy = true;
	} finally {
		writer.releaseLock();
	}
	consoleLog(`0-rtt data write finish: need_retry=${needRetryByProxy}, use_proxy=${useProxy}`);
	if (needRetryByProxy && !useProxy) {
		consoleLog(`Retry handshake with remote because of writable stream timeout`);
		return handshakeWithRemote(proxySocket, webSocket, subProtocolData, useProxy = true);
	}

	// 3.read back
	(async () => {
		consoleLog(`tcpsocket readable stream start: ${proxySocket.tcpSocket}`);
		let needRetryByProxy = true;
		await proxySocket.tcpSocket.readable.pipeTo(new WritableStream({
			async write(chunk, controller) {
				needRetryByProxy = false;

				consoleLog(`received data from remote: ${chunk.byteLength}`);
				const dataToSend = subProtocolData.responseHeader ? await new Blob([subProtocolData.responseHeader, chunk]).arrayBuffer() : chunk;
				webSocket.send(dataToSend);
				subProtocolData.responseHeader = null;
				consoleLog(`received data from remote: finish`);
			}
		}));
		consoleLog(`tcpsocket readable stream finish: need_retry=${needRetryByProxy}, use_proxy=${useProxy}`);
		if (needRetryByProxy && !useProxy) {
			consoleLog(`Retry handshake with remote (use proxy) because of readstream empty`);
			return handshakeWithRemote(proxySocket, webSocket, subProtocolData, useProxy = true);
		}
	})();
}

// 1.3.2.1 connectBySocks5
// ref: https://en.wikipedia.org/wiki/SOCKS#SOCKS5
async function connectBySocks5(remoteAddressType, remoteAddress, remotePort) {
	const [username, password, hostname, port] = socks5Proxy.split(/[:@]/);
	const socks5ProxySocket = connect({ hostname, port: Number(port) });
	consoleLog(`connect socks5: ${hostname}:${port}`);

	// Client greeting
	const clientGreeting = new Uint8Array([
		0x05, // VER, SOCKS version (0x05)
		0x02, // NAUTH, Number of authentication methods supported, uint8
		// AUTH, Authentication methods, 1 byte per method supported
		0x00, // 0x00: No authentication
		0x02, // 0x02: Username/password
	]);
	const writer = socks5ProxySocket.writable.getWriter();
	// await writer.write(clientGreeting);
	try {
		await Promise.race([
			writer.write(clientGreeting),
			new Promise((_, reject) => setTimeout(() => reject(new Error("Write operation timed out")), 3000))
		]);
	} catch (error) {
		consoleLog(`socks5 proxy write error: ${error}`);
		throw new Error(error);
	}
	consoleLog(`client greeting finish`);

	// Server choice
	const reader = socks5ProxySocket.readable.getReader();
	const serverChoiceRes = (await reader.read()).value;
	if (serverChoiceRes[0] !== 0x05) { // VER, SOCKS version (0x05)
		throw new Error(`upexpected socks version(${serverChoiceRes[0]}), expected 0x05`);
	}
	consoleLog(`server choice finish`);

	// CAUTH, chosen authentication method
	if (serverChoiceRes[1] === 0xff) { // 0xFF, no acceptable methods were offered
		throw new Error(`socks server choice: no acceptable methods were offered`);
	}
	if (serverChoiceRes[1] === 0x02) { // 0x02, username and password authentication
		// Client authentication request, 0x02
		const authRequest = new Uint8Array([
			0x01, // VER, 0x01 for current version of username/password authentication
			username.length, // IDLEN, username length, uint8
			...new TextEncoder().encode(username), // ID, username as bytestring
			password.length, // PWLEN, password length, uint8
			...new TextEncoder().encode(password) // PW, password as bytestring
		]);
		await writer.write(authRequest);
		// Server response, 0x02
		const authRes = (await reader.read()).value;
		if (authRes[0] !== 0x01) { // VER, 0x01 for current version of username/password authentication
			throw new Error(`upexpected auth version(${authRes[0]}), expected 0x01`);
		}
		if (authRes[1] !== 0x00) { // STATUS, 0x00 success, otherwise failure, connection must be closed
			throw new Error(`socks auth failure, status: ${authRes[1]}`);
		}
	}
	consoleLog(`CAUTH finish`);

	// SOCKS5 address
	let socks5Address;
	switch (remoteAddressType) {
		case 0x01: // IPv4 address
			socks5Address = new Uint8Array(
				[0x01, ...remoteAddress.split('.').map(Number)]
			);
			break;
		case 0x03: // Domain name
			socks5Address = new Uint8Array(
				[0x03, remoteAddress.length, ...new TextEncoder().encode(remoteAddress)]
			);
			break;
		case 0x04: // IPv6 address
			socks5Address = new Uint8Array(
				[0x04, ...remoteAddress.split(':').flatMap(x => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]
			);
			break;
		default:
			throw new Error(`unsupported address type: ${remoteAddressType}`);
	}

	// Client connection request
	const clientConnRequest = new Uint8Array([
		5, // VER, SOCKS version (0x05)
		1, // CMD, command code, 0x01: establish a TCP/IP stream connection
		0, // RSV, reserved, must be 0x00
		...socks5Address, // DSTADDR, destination address
		remotePort >> 8, remotePort & 0xff, // DSTPORT, 2 bytes, port number in a network byte order
	]);
	await writer.write(clientConnRequest);
	consoleLog(`client connection finish`);

	// Response packet from server
	const res = (await reader.read()).value;
	if (res[0] !== 0x05) { // VER, SOCKS version (0x05)
		throw new Error(`upexpected socks version(${serverChoiceRes[0]}), expected 0x05`);
	}
	consoleLog(`response packet from server finish`);

	// STATUS, status code
	switch (res[1]) {
		case 0x00:
			consoleLog(`connect by socks5 success`);
			break;
		case 0x01:
			throw new Error(`socks server response status: 0x01, general failure`);
		case 0x02:
			throw new Error(`socks server response status: 0x02, connection not allowed by ruleset`);
		case 0x03:
			throw new Error(`socks server response status: 0x03, network unreachable`);
		case 0x04:
			throw new Error(`socks server response status: 0x04, host unreachable`);
		case 0x05:
			throw new Error(`socks server response status: 0x05, connection refused by destination host`);
		case 0x06:
			throw new Error(`socks server response status: 0x06, TTL expired`);
		case 0x07:
			throw new Error(`socks server response status: 0x07, command not supported / protocol error`);
		case 0x08:
			throw new Error(`socks server response status: 0x08, address type not supported`);
		default:
			throw new Error(`unknown socks server response status: ${res[1]}`);

	}

	writer.releaseLock();
	reader.releaseLock();
	return socks5ProxySocket;
}

// 2 handlerHTTPRequest
async function handlerHTTPRequest(request) {
	return new Response(`${JSON.stringify(request.cf)}`);
}
