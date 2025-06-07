import { exists } from "https://deno.land/std/fs/exists.ts";

// استخدام نفس UUID الثابت من الكود الأصلي
const userID = 'e5185305-1984-4084-81e0-f77271159c62';
const proxyIP = Deno.env.get('PROXYIP') || '';

// تأكد من أن UUID صحيح
if (!isValidUUID(userID)) {
  throw new Error('UUID is not valid');
}

console.log(Deno.version);
console.log(`Using fixed UUID: ${userID}`);

// تحسين إعدادات Deno.serve لدعم عدد كبير من الاتصالات
Deno.serve(
  {
    handler: async (request: Request) => {
      const upgrade = request.headers.get('upgrade')?.toLowerCase();
      if (upgrade !== 'websocket') {
        return new Response('Not found', { status: 404 });
      }
      return await vlessOverWSHandler(request);
    },
    // إعدادات متقدمة لتحسين الأداء
    maxConnections: 0, // إزالة حد الاتصالات
    keepAliveTimeout: 30000, // الإبقاء على الاتصال مفتوحًا لمدة 30 ثانية
    highWaterMark: 1024 * 1024, // زيادة حجم الـ Buffer للتعامل مع البيانات الكبيرة
  }
);

async function vlessOverWSHandler(request: Request) {
  const { socket, response } = Deno.upgradeWebSocket(request, {
    idleTimeout: 60, // زيادة وقت الخمول لتجنب إغلاق الاتصالات المفتوحة
  });
  let address = '';
  let portWithRandomLog = '';
  const log = (info: string, event = '') => {
    console.log(`[${address}:${portWithRandomLog}] ${info}`, event);
  };
  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const readableWebSocketStream = makeReadableWebSocketStream(socket, earlyDataHeader, log);
  let remoteSocketWapper: any = { value: null };
  let udpStreamWrite: any = null;
  let isDns = false;

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          try {
            if (isDns && udpStreamWrite) {
              return udpStreamWrite(chunk);
            }
            if (remoteSocketWapper.value) {
              const writer = remoteSocketWapper.value.writable.getWriter();
              await writer.write(chunk); // إزالة تحويل غير ضروري إلى Uint8Array
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
            portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp ' : 'tcp '}`;
            if (hasError) {
              controller.error(message);
              return;
            }
            if (isUDP) {
              if (portRemote === 53) {
                isDns = true;
              } else {
                controller.error('UDP proxy only enable for DNS which is port 53');
                return;
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
          } catch (err) {
            controller.error(err);
          }
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
  async function connectAndWrite(address: string, port: number) {
    const tcpSocket = await Deno.connect({
      port,
      hostname: address,
      transport: 'tcp',
      // تفعيل keepAlive لتحسين الأداء
      keepAlive: true,
    });

    remoteSocket.value = tcpSocket;
    log(`connected to ${address}:${port}`);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
  }

  async function retry() {
    try {
      const tcpSocket = await connectAndWrite(proxyIP || addressRemote, portRemote);
      remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);
    } catch (err) {
      log('Retry failed', err);
    }
  }

  try {
    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
    remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry, log);
  } catch (err) {
    log('Connection failed, retrying', err);
    retry();
  }
}

function makeReadableWebSocketStream(webSocketServer: WebSocket, earlyDataHeader: string, log: (info: string, event?: string) => void) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener('message', (event) => {
        if (readableStreamCancel) return;
        controller.enqueue(event.data);
      });

      webSocketServer.addEventListener('close', () => {
        safeCloseWebSocket(webSocketServer);
        if (readableStreamCancel) return;
        controller.close();
      });

      webSocketServer.addEventListener('error', (err) => {
        log('webSocketServer error');
        controller.error(err);
      });

      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },
    cancel(reason) {
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
  const version = new Uint8Array(vlessBuffer.slice(0, 1));
  if (stringify(new Uint8Array(vlessBuffer.slice(1, 17))) !== userID) {
    return { hasError: true, message: 'invalid user' };
  }

  const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
  const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 19 + optLength))[0];
  let isUDP = command === 2;
  if (command !== 1 && command !== 2) {
    return { hasError: true, message: `command ${command} is not supported` };
  }

  const portIndex = 19 + optLength;
  const portRemote = new DataView(vlessBuffer.slice(portIndex, portIndex + 2)).getUint16(0);
  let addressIndex = portIndex + 2;
  const addressType = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1))[0];
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
      const ipv6: string[] = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(':');
      break;
    default:
      return { hasError: true, message: `invalid addressType ${addressType}` };
  }

  if (!addressValue) {
    return { hasError: true, message: `addressValue is empty, addressType ${addressType}` };
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    addressType,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    vlessVersion: version,
    isUDP,
  };
}

async function remoteSocketToWS(remoteSocket: Deno.TcpConn, webSocket: WebSocket, vlessResponseHeader: Uint8Array, retry: (() => Promise<void>) | null, log: (info: string, event?: string) => void) {
  let hasIncomingData = false;
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          hasIncomingData = true;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            throw new Error('WebSocket is not open');
          }
          if (vlessResponseHeader) {
            webSocket.send(new Uint8Array([...vlessResponseHeader, ...chunk]));
            vlessResponseHeader = null;
          } else {
            webSocket.send(chunk);
          }
        },
        close() {
          log(`remoteConnection closed, hasIncomingData: ${hasIncomingData}`);
        },
        abort(reason) {
          log(`remoteConnection aborted`, reason);
        },
      })
    )
    .catch((error) => {
      log(`remoteSocketToWS error`, error);
      safeCloseWebSocket(webSocket);
      if (!hasIncomingData && retry) {
        log(`Retrying connection`);
        retry();
      }
    });
}

function base64ToArrayBuffer(base64Str: string) {
  if (!base64Str) return { error: null };
  try {
    base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
    const decode = atob(base64Str);
    const arrayBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0)).buffer;
    return { earlyData: arrayBuffer, error: null };
  } catch (error) {
    return { error };
  }
}

function isValidUUID(uuid: string): boolean {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
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

async function handleUDPOutBound(webSocket: WebSocket, vlessResponseHeader: Uint8Array, log: (info: string) => void) {
  let isVlessHeaderSent = false;
  const transformStream = new TransformStream({
    transform(chunk, controller) {
      let index = 0;
      while (index < chunk.byteLength) {
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
        const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPacketLength));
        index += 2 + udpPacketLength;
        controller.enqueue(udpData);
      }
    },
  });

  transformStream.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          try {
            const resp = await fetch('https://1.1.1.1/dns-query', {
              method: 'POST',
              headers: { 'content-type': 'application/dns-message' },
              body: chunk,
            });
            const dnsQueryResult = await resp.arrayBuffer();
            const udpSize = dnsQueryResult.byteLength;
            const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
            if (webSocket.readyState === WS_READY_STATE_OPEN) {
              log(`DNS success, message length: ${udpSize}`);
              const data = isVlessHeaderSent
                ? [udpSizeBuffer, dnsQueryResult]
                : [vlessResponseHeader, udpSizeBuffer, dnsQueryResult];
              webSocket.send(await new Blob(data).arrayBuffer());
              isVlessHeaderSent = true;
            }
          } catch (error) {
            log(`DNS UDP error: ${error}`);
          }
        },
      })
    )
    .catch((error) => {
      log(`DNS UDP stream error: ${error}`);
    });

  return {
    write(chunk: Uint8Array) {
      transformStream.writable.getWriter().write(chunk).catch((err) => log(`UDP write error: ${err}`));
    },
  };
}
