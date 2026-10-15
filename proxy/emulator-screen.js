/**
 * Emulator gRPC screen streaming.
 *
 * When Loupe starts an emulator with `-grpc <port>`, this module connects to
 * that port and streams the display via `streamScreenshot`. The host GPU
 * renders the frames directly — no guest-side encoding, no scrcpy, no ADB
 * bottleneck. Touch, key and mouse events go back over the same gRPC channel.
 */
import path from 'node:path';
import os from 'node:os';
import { WebSocketServer } from 'ws';
import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import { handleProtocols } from './auth.js';

const SDK_ROOT = () => process.env.ANDROID_HOME || process.env.ANDROID_SDK_ROOT ||
  path.join(process.env.LOUPE_HOME || path.join(os.homedir(), '.loupe'), 'android-sdk');

const PROTO_PATH = () => path.join(SDK_ROOT(), 'emulator', 'lib', 'emulator_controller.proto');

let EmulatorController = null;

function loadProto() {
  if (EmulatorController) return;
  const packageDefinition = protoLoader.loadSync(PROTO_PATH(), {
    keepCase: true,
    longs: Number,
    enums: String,
    defaults: true,
    oneofs: true,
  });
  const pkg = grpc.loadPackageDefinition(packageDefinition);
  EmulatorController = pkg.android.emulation.control.EmulatorController;
}

function createClient(grpcPort) {
  loadProto();
  return new EmulatorController(
    `localhost:${grpcPort}`,
    grpc.credentials.createInsecure()
  );
}

/**
 * Attaches the emulator screen WebSocket to an HTTP server.
 *
 * Protocol:
 *   ws://…/__loupe/emulator/screen?grpc=<port>&width=<px>
 *
 * Server → client:
 *   - text  `{"type":"size","width":W,"height":H}` on first frame & resize
 *   - binary  raw PNG bytes for each frame
 *   - text  `{"type":"error","message":"…"}` on stream errors
 *
 * Client → server (JSON text):
 *   - `{"type":"touch","x":int,"y":int,"pressure":int,"id":int}`
 *   - `{"type":"key","key":"…"}` or `{"type":"key","text":"…"}`
 *   - `{"type":"mouse","x":int,"y":int,"buttons":int}`
 */
export function attachEmulatorScreen(server, { accessOk }) {
  const wss = new WebSocketServer({ noServer: true, handleProtocols });

  server.on('upgrade', (req, socket, head) => {
    const url = new URL(req.url, 'http://x');
    if (url.pathname !== '/__loupe/emulator/screen') return;
    if (!accessOk(req)) { socket.destroy(); return; }

    wss.handleUpgrade(req, socket, head, (ws) => {
      const grpcPort = Number(url.searchParams.get('grpc'));
      const desiredWidth = Number(url.searchParams.get('width')) || 540;

      if (!grpcPort) { ws.close(1008, 'grpc port required'); return; }

      let client;
      try {
        client = createClient(grpcPort);
      } catch (e) {
        ws.close(1011, 'gRPC client failed: ' + e.message);
        return;
      }

      let stream = null;
      let closed = false;
      let lastW = 0;
      let lastH = 0;

      stream = client.streamScreenshot({
        format: 0, // PNG
        width: desiredWidth,
        height: 0,
        display: 0,
      });

      stream.on('data', (image) => {
        if (closed || ws.readyState !== ws.OPEN) return;
        if (!image.image || image.image.length === 0) return;

        const w = image.format?.width || 0;
        const h = image.format?.height || 0;

        if (w !== lastW || h !== lastH) {
          lastW = w;
          lastH = h;
          ws.send(JSON.stringify({ type: 'size', width: w, height: h }));
        }

        ws.send(image.image, { binary: true });
      });

      stream.on('error', (e) => {
        if (!closed && ws.readyState === ws.OPEN) {
          ws.send(JSON.stringify({ type: 'error', message: e.message }));
        }
      });

      stream.on('end', () => {
        if (!closed && ws.readyState === ws.OPEN) ws.close(1000, 'stream ended');
      });

      ws.on('message', (data) => {
        if (closed) return;
        try {
          const msg = JSON.parse(data.toString());
          if (msg.type === 'touch') {
            client.sendTouch({
              touches: [{
                x: msg.x | 0,
                y: msg.y | 0,
                identifier: msg.id || 0,
                pressure: msg.pressure ?? 1024,
                touch_major: 0,
                touch_minor: 0,
              }],
              display: 0,
            }, () => {});
          } else if (msg.type === 'key') {
            client.sendKey({
              eventType: msg.eventType || 'keypress',
              key: msg.key || '',
              text: msg.text || '',
            }, () => {});
          } else if (msg.type === 'mouse') {
            client.sendMouse({
              x: msg.x | 0,
              y: msg.y | 0,
              buttons: msg.buttons || 0,
              display: 0,
            }, () => {});
          }
        } catch { /* malformed */ }
      });

      const cleanup = () => {
        closed = true;
        try { stream?.cancel(); } catch {}
        try { client?.close(); } catch {}
        stream = null;
        client = null;
      };

      ws.on('close', cleanup);
      ws.on('error', cleanup);
    });
  });
}
