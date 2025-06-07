import { exists } from "https://deno.land/std/fs/exists.ts";

// الثوابت العامة
const DNS_QUERY_URL = 'https://1.1.1.1/dns-query';
const DEFAULT_PORT = 443;
const BUFFER_SIZE = 4096;
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// استخدام نفس UUID الثابت من الكود الأصلي
const userID = '0197481f-d321-7786-8a31-800923b55298';
const proxyIP = Deno.env.get('PROXYIP') || '';

// تأكد من أن UUID صحيح
if (!isValidUUID(userID)) {
  throw new Error('UUID is not valid');
}

console.log(Deno.version);
console.log(`Using fixed UUID: ${userID}`);

Deno.serve(async (request: Request) => {
  const upgrade = request.headers.get('upgrade') || '';
  if (upgrade.toLowerCase() !== 'websocket') {
    return new Response('Not found', { status: 404 });
  }
  return await vlessOverWSHandler(request);
});

async function vlessOverWSHandler(request: Request) {
  const { socket, response } = Deno.upgradeWebSocket(request);
  let address = '';
  let portWithRandomLog = '';
  const log = (info: string, event = '') => {
    console.log(`[${address}:${portWithRandomLog}] ${info}`, event);
  };
  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const readableWebSocketStream = makeReadableWebSocketStream(socket, earlyDataHeader, log);
  let remoteSocketWapper: any = {
    value: null,
  };
  let udpStreamWrite: any = null;
  let isDns = false;

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (isDns && udpStreamWrite) {
            return udpStreamWrite(chunk);
          }
          if (remoteSocketWapper.value) {
            const writer = remoteSocketWapper.value.writable.getWriter();
            await writer.write(new Uint8Array(chunk));
            writer.releaseLock();
            return;
          }

          const {
            hasError,
            message,
            portRemote = 443,
            addressRemote = '',
            rawDataIndex,
            vlessVersion = new Uint8Array([0, 0]),
            isUDP,
          } = processVlessHeader(chunk, userID);
          address = addressRemote;
          portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp ' : 'tcp '} `;
          
          if (hasError) {
            throw new Error(message);
          }
          if (isUDP) {
            if (portRemote === 53) {
              isDns = true;
            } else {
              throw new Error('UDP proxy only enable for DNS which is port 53');
            }
          }
          
          const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
          const rawClientData = chunk.slice(rawDataIndex);

          if (isDns) {
            const { write } = await handleUDPOutBound(socket, vlessResponseHeader, log);
            udpStreamWrite = write;
            udpStreamWrite(rawClientData);
            return;
          }
          
          handleTCPOutBound(
            remoteSocketWapper,
            addressRemote,
            portRemote,
            rawClientData,
            socket,
            vlessResponseHeader,
            log
          );
        },
        close() {
          log(`readableWebSocketStream is closed`);
        },
        abort(reason) {
          log(`readableWebSocketStream is aborted`, JSON.stringify(reason));
        },
      })
    )
    .catch((err) => {
      log('readableWebSocketStream pipeTo error', err);
    });

  return response;
}

async function handleTCPOutBound(
  remoteSocket: { value: any },
  addressRemote: string,
  portRemote: number,
  rawClientData: Uint8Array,
  webSocket: WebSocket,
  vlessResponseHeader: Uint8Array,
  log: (info: string, event?: string) => void
) {
  const connectOptions = {
    port: portRemote,
    hostname: proxyIP || addressRemote,
    transport: "tcp",
  };

  async function connectAndWrite() {
    try {
      const tcpSocket = await Deno.connect(connectOptions);
      remoteSocket.value = tcpSocket;
      log(`Connected to ${connectOptions.hostname}:${connectOptions.port}`);

      await tcpSocket.write(rawClientData);
      return tcpSocket;
    } catch (error) {
      log(`Connection error: ${error}`);
      throw error;
    }
  }

  async function retry() {
    try {
      const tcpSocket = await connectAndWrite();
      remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);
    } catch (error) {
      log(`Retry failed: ${error}`);
    }
  }

  try {
    const tcpSocket = await connectAndWrite();
    remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry, log);
  } catch (error) {
    if (retry) await retry();
  }
}

function makeReadableWebSocketStream(
  webSocketServer: WebSocket,
  earlyDataHeader: string,
  log: (info: string, event?: string) => void
) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.onmessage = (event) => {
        if (readableStreamCancel) return;
        controller.enqueue(event.data);
      };

      webSocketServer.onclose = () => {
        safeCloseWebSocket(webSocketServer);
        if (!readableStreamCancel) controller.close();
      };

      webSocketServer.onerror = (err) => {
        log('webSocketServer error', err);
        controller.error(err);
      };

      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },
    cancel(reason) {
      if (readableStreamCancel) return;
      log(`ReadableStream canceled: ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });

  return stream;
}

function processVlessHeader(vlessBuffer: ArrayBuffer, userID: string) {
  if (vlessBuffer.byteLength < 24) {
    return { hasError: true, message: 'invalid data' };
  }

  const dataView = new DataView(vlessBuffer);
  const version = new Uint8Array(vlessBuffer.slice(0, 1));
  
  const uuidBytes = new Uint8Array(vlessBuffer.slice(1, 17));
  if (unsafeStringify(uuidBytes) !== userID) {
    return { hasError: true, message: 'invalid user' };
  }

  const optLength = dataView.getUint8(17);
  const command = dataView.getUint8(18 + optLength);
  const isUDP = command === 2;
  
  if (command !== 1 && !isUDP) {
    return { hasError: true, message: `unsupported command: ${command}` };
  }

  const portRemote = dataView.getUint16(18 + optLength + 1);
  const addressType = dataView.getUint8(18 + optLength + 3);
  let addressValue = '';
  let addressValueIndex = 18 + optLength + 4;
  
  switch (addressType) {
    case 1:
      addressValue = [
        dataView.getUint8(addressValueIndex),
        dataView.getUint8(addressValueIndex + 1),
        dataView.getUint8(addressValueIndex + 2),
        dataView.getUint8(addressValueIndex + 3)
      ].join('.');
      addressValueIndex += 4;
      break;
      
    case 2:
      const domainLength = dataView.getUint8(addressValueIndex++);
      addressValue = new TextDecoder().decode(
        vlessBuffer.slice(addressValueIndex, addressValueIndex + domainLength)
      );
      addressValueIndex += domainLength;
      break;
      
    case 3:
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(addressValueIndex + i * 2).toString(16));
      }
      addressValue = ipv6.join(':');
      addressValueIndex += 16;
      break;
      
    default:
      return { hasError: true, message: `invalid addressType: ${addressType}` };
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    addressType,
    portRemote,
    rawDataIndex: addressValueIndex,
    vlessVersion: version,
    isUDP,
  };
}

async function remoteSocketToWS(
  remoteSocket: Deno.TcpConn,
  webSocket: WebSocket,
  vlessResponseHeader: Uint8Array,
  retry: (() => Promise<void>) | null,
  log: (info: string, event?: string) => void
) {
  let hasIncomingData = false;
  const writer = webSocket.send.bind(webSocket);

  try {
    for await (const chunk of remoteSocket.readable) {
      hasIncomingData = true;
      if (webSocket.readyState !== WS_READY_STATE_OPEN) {
        throw new Error('WebSocket not open');
      }

      if (vlessResponseHeader) {
        writer(new Uint8Array([...vlessResponseHeader, ...chunk]));
        vlessResponseHeader = null;
      } else {
        writer(chunk);
      }
    }
  } catch (error) {
    log(`remoteSocketToWS error: ${error}`);
    safeCloseWebSocket(webSocket);
  } finally {
    log(`remoteConnection closed, had data: ${hasIncomingData}`);
    if (!hasIncomingData && retry) {
      log('Retrying connection...');
      await retry();
    }
  }
}

async function handleUDPOutBound(
  webSocket: WebSocket,
  vlessResponseHeader: Uint8Array,
  log: (info: string) => void
) {
  let isVlessHeaderSent = false;
  const transformStream = new TransformStream({
    transform(chunk, controller) {
      try {
        const dataView = new DataView(chunk.buffer);
        for (let index = 0; index < chunk.byteLength;) {
          const udpPakcetLength = dataView.getUint16(index);
          index += 2;
          controller.enqueue(chunk.slice(index, index + udpPakcetLength));
          index += udpPakcetLength;
        }
      } catch (error) {
        log(`UDP transform error: ${error}`);
      }
    },
  });

  const writer = transformStream.writable.getWriter();

  transformStream.readable.pipeTo(new WritableStream({
    async write(chunk) {
      try {
        const resp = await fetch(DNS_QUERY_URL, {
          method: 'POST',
          headers: { 'content-type': 'application/dns-message' },
          body: chunk,
        });
        
        const dnsQueryResult = await resp.arrayBuffer();
        const udpSize = dnsQueryResult.byteLength;
        const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
        
        if (webSocket.readyState === WS_READY_STATE_OPEN) {
          const chunks = isVlessHeaderSent 
            ? [udpSizeBuffer, dnsQueryResult]
            : [vlessResponseHeader, udpSizeBuffer, dnsQueryResult];
          
          webSocket.send(await new Blob(chunks).arrayBuffer());
          isVlessHeaderSent = true;
        }
      } catch (error) {
        log(`DNS query error: ${error}`);
      }
    },
    abort(error) {
      log(`UDP write abort: ${error}`);
    }
  })).catch(error => log(`UDP pipe error: ${error}`));

  return {
    write(chunk: Uint8Array) {
      writer.write(chunk).catch(error => log(`UDP write error: ${error}`));
    },
  };
}

function base64ToArrayBuffer(base64Str: string) {
  if (!base64Str) {
    return { error: null };
  }
  try {
    base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}

function isValidUUID(uuid: string): boolean {
  return UUID_REGEX.test(uuid);
}

function safeCloseWebSocket(socket: WebSocket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {
    console.error('safeCloseWebSocket error', error);
  }
}

const byteToHex: string[] = [];
for (let i = 0; i < 256; ++i) {
  byteToHex.push((i + 256).toString(16).slice(1));
}

function unsafeStringify(arr: Uint8Array, offset = 0) {
  return (
    byteToHex[arr[offset + 0]] +
    byteToHex[arr[offset + 1]] +
    byteToHex[arr[offset + 2]] +
    byteToHex[arr[offset + 3]] +
    '-' +
    byteToHex[arr[offset + 4]] +
    byteToHex[arr[offset + 5]] +
    '-' +
    byteToHex[arr[offset + 6]] +
    byteToHex[arr[offset + 7]] +
    '-' +
    byteToHex[arr[offset + 8]] +
    byteToHex[arr[offset + 9]] +
    '-' +
    byteToHex[arr[offset + 10]] +
    byteToHex[arr[offset + 11]] +
    byteToHex[arr[offset + 12]] +
    byteToHex[arr[offset + 13]] +
    byteToHex[arr[offset + 14]] +
    byteToHex[arr[offset + 15]]
  ).toLowerCase();
}

function stringify(arr: Uint8Array, offset = 0) {
  const uuid = unsafeStringify(arr, offset);
  if (!isValidUUID(uuid)) {
    throw TypeError('Stringified UUID is invalid');
  }
  return uuid;
}
