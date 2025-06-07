// Trojan over WebSocket (Deno)
import { exists } from "https://deno.land/std/fs/exists.ts";

const trojanPassword = Deno.env.get("TROJAN_PASSWORD") || "mypassword";
const proxyIP = Deno.env.get("PROXYIP") || "";

console.log(Deno.version);
console.log(`Trojan Password: ${trojanPassword}`);

Deno.serve(async (request: Request) => {
  const upgrade = request.headers.get("upgrade") || "";
  if (upgrade.toLowerCase() != "websocket") {
    return new Response("Not found", { status: 404 });
  } else {
    return await trojanOverWSHandler(request);
  }
});

async function trojanOverWSHandler(request: Request) {
  const { socket, response } = Deno.upgradeWebSocket(request);
  let address = "";
  let portWithRandomLog = "";
  const log = (info: string, event = '') => {
    console.log(`[${address}:${portWithRandomLog}] ${info}`, event);
  };

  const readableWebSocketStream = makeReadableWebSocketStream(socket, log);
  let remoteSocketWapper: any = { value: null };

  readableWebSocketStream.pipeTo(
    new WritableStream({
      async write(chunk, controller) {
        if (remoteSocketWapper.value) {
          const writer = remoteSocketWapper.value.writable.getWriter();
          await writer.write(new Uint8Array(chunk));
          writer.releaseLock();
          return;
        }

        const {
          hasError,
          message,
          portRemote,
          addressRemote,
          rawDataIndex,
        } = processTrojanHeader(chunk.buffer);

        address = addressRemote;
        portWithRandomLog = `${portRemote}--${Math.random()} tcp`;

        if (hasError) {
          throw new Error(message);
        }

        const rawClientData = chunk.slice(rawDataIndex);
        handleTCPOutBound(
          remoteSocketWapper,
          addressRemote,
          portRemote,
          rawClientData,
          socket,
          null,
          log
        );
      },
      close() {
        log(`readableWebSocketStream is closed`);
      },
      abort(reason) {
        log(`readableWebSocketStream aborted`, JSON.stringify(reason));
      },
    })
  ).catch((err) => {
    log("readableWebSocketStream pipeTo error", err);
  });

  return response;
}

function processTrojanHeader(buffer: ArrayBuffer) {
  const data = new Uint8Array(buffer);
  const str = new TextDecoder().decode(data);
  const index = str.indexOf("\r\n");
  if (index === -1) {
    return { hasError: true, message: "Missing Trojan password delimiter" };
  }

  const password = str.slice(0, index);
  if (password !== trojanPassword) {
    return { hasError: true, message: "Invalid Trojan password" };
  }

  const rawDataIndex = index + 2;
  const rawData = data.slice(rawDataIndex);

  if (rawData.length < 4) {
    return { hasError: true, message: "Invalid Trojan request data" };
  }

  const cmd = rawData[0];
  if (cmd !== 1) {
    return { hasError: true, message: "Only TCP (cmd=1) supported" };
  }

  const addressType = rawData[1];
  let address = "";
  let port = 0;
  let offset = 2;

  if (addressType === 1) {
    address = rawData.slice(offset, offset + 4).join('.');
    offset += 4;
  } else if (addressType === 3) {
    const domainLen = rawData[offset];
    offset += 1;
    address = new TextDecoder().decode(rawData.slice(offset, offset + domainLen));
    offset += domainLen;
  } else if (addressType === 4) {
    const view = new DataView(rawData.buffer, rawData.byteOffset + offset, 16);
    const segments = [];
    for (let i = 0; i < 8; i++) {
      segments.push(view.getUint16(i * 2).toString(16));
    }
    address = segments.join(":" );
    offset += 16;
  } else {
    return { hasError: true, message: "Unknown address type" };
  }

  port = (rawData[offset] << 8) + rawData[offset + 1];
  offset += 2;

  return {
    hasError: false,
    addressRemote: address,
    portRemote: port,
    rawDataIndex: rawDataIndex + offset,
  };
}

async function handleTCPOutBound(
  remoteSocket: { value: any },
  addressRemote: string,
  portRemote: number,
  rawClientData: Uint8Array,
  webSocket: WebSocket,
  _header: any,
  log: (info: string, event?: string) => void
) {
  const tcpSocket = await Deno.connect({ port: portRemote, hostname: proxyIP || addressRemote });
  remoteSocket.value = tcpSocket;
  log(`connected to ${addressRemote}:${portRemote}`);
  const writer = tcpSocket.writable.getWriter();
  await writer.write(rawClientData);
  writer.releaseLock();

  remoteSocketToWS(tcpSocket, webSocket, null, null, log);
}

function makeReadableWebSocketStream(webSocketServer: WebSocket, log: (info: string, event?: string) => void) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        if (readableStreamCancel) return;
        controller.enqueue(event.data);
      });
      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        if (!readableStreamCancel) controller.close();
      });
      webSocketServer.addEventListener("error", (err) => {
        log("webSocketServer has error");
        controller.error(err);
      });
    },
    cancel(reason) {
      if (!readableStreamCancel) {
        log(`ReadableStream canceled: ${reason}`);
        readableStreamCancel = true;
        safeCloseWebSocket(webSocketServer);
      }
    },
  });
  return stream;
}

async function remoteSocketToWS(remoteSocket: Deno.TcpConn, webSocket: WebSocket, _header: Uint8Array | null, _retry: (() => Promise<void>) | null, log: (info: string, event?: string) => void) {
  await remoteSocket.readable.pipeTo(
    new WritableStream({
      async write(chunk, controller) {
        if (webSocket.readyState !== WS_READY_STATE_OPEN) {
          controller.error("WebSocket not open");
        } else {
          webSocket.send(chunk);
        }
      },
      close() {
        log("Remote socket closed");
      },
      abort(reason) {
        console.error("Remote socket error", reason);
      },
    })
  ).catch((err) => {
    console.error("remoteSocketToWS error", err);
    safeCloseWebSocket(webSocket);
  });
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
function safeCloseWebSocket(socket: WebSocket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {
    console.error("safeCloseWebSocket error", error);
  }
}
