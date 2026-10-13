/* SoMi-Melden – gemeinsamer Kern für Lehrer-App und Schülerseite.
   Enthält: Relay-Adressen, einen kleinen MQTT-3.1.1-Client über WebSocket,
   Verschlüsselung und die Ableitung pseudonymer Kennungen.
   Über das Netz gehen nur verschlüsselte Nachrichten mit pseudonymen Kennungen – nie Namen. */
(function () {
  "use strict";

  /* Relays: Beide Seiten verbinden sich mit allen Adressen gleichzeitig.
     Fällt einer aus, läuft alles über den anderen weiter.
     Zum Testen lässt sich die Liste mit ?broker=wss://…,wss://… überschreiben. */
  const DEFAULT_BROKERS = [
    "wss://broker.hivemq.com:8884/mqtt",
    "wss://broker.emqx.io:8084/mqtt"
  ];
  function brokers() {
    try {
      const q = new URLSearchParams(location.search).get("broker");
      if (q) return q.split(",").map(s => s.trim()).filter(Boolean);
    } catch (e) {}
    return DEFAULT_BROKERS;
  }

  /* ---------- Codes ---------- */
  const ALPHA = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"; // ohne 0/O, 1/I/L
  function randCode(n) {
    const out = [], buf = new Uint32Array(n);
    crypto.getRandomValues(buf);
    for (let i = 0; i < n; i++) out.push(ALPHA[buf[i] % ALPHA.length]);
    return out.join("");
  }
  function norm(s) {
    return [...String(s || "").toUpperCase()].filter(c => ALPHA.includes(c)).join("");
  }
  const valid = (s, n) => s.length === n && [...s].every(c => ALPHA.includes(c));

  /* ---------- Krypto ---------- */
  const te = new TextEncoder(), td = new TextDecoder();
  const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
  async function sha(s) { return crypto.subtle.digest("SHA-256", te.encode(s)); }
  async function hmac(keyStr, msg) {
    const k = await crypto.subtle.importKey("raw", te.encode(keyStr), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return hex(await crypto.subtle.sign("HMAC", k, te.encode(msg)));
  }
  async function room(roomCode) {
    const base = "somi/v1/" + hex(await sha("somi|topic|" + roomCode)).slice(0, 24);
    const key = await crypto.subtle.importKey("raw", await sha("somi|key|" + roomCode), "AES-GCM", false, ["encrypt", "decrypt"]);
    return {
      code: roomCode,
      stateTopic: base + "/s",
      raiseTopic: base + "/r",
      async enc(obj) {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, te.encode(JSON.stringify(obj))));
        const out = new Uint8Array(12 + ct.length); out.set(iv); out.set(ct, 12); return out;
      },
      async dec(bytes) {
        try {
          const b = new Uint8Array(bytes);
          if (b.length < 13) return null;
          const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b.slice(0, 12) }, key, b.slice(12));
          return JSON.parse(td.decode(pt));
        } catch (e) { return null; }
      }
    };
  }
  /* Pseudonyme Kennung einer Person (für Bestätigungen) und Nachweis pro Meldephase.
     Wer nur die Kennung kennt, kann damit keine neue Meldung fälschen. */
  const personId = (roomCode, code) => hmac(code, "id|" + roomCode).then(h => h.slice(0, 12));
  const token = (code, round) => hmac(code, "tok|" + round).then(h => h.slice(0, 16));

  /* ---------- Minimaler MQTT-3.1.1-Client (QoS 0) ---------- */
  function str(s) { const b = te.encode(s); const o = new Uint8Array(2 + b.length); o[0] = b.length >> 8; o[1] = b.length & 255; o.set(b, 2); return o; }
  function packet(head, ...parts) {
    let len = parts.reduce((a, p) => a + p.length, 0);
    const rl = []; do { let d = len % 128; len = Math.floor(len / 128); if (len > 0) d |= 128; rl.push(d); } while (len > 0);
    const total = 1 + rl.length + parts.reduce((a, p) => a + p.length, 0);
    const out = new Uint8Array(total); out[0] = head; out.set(rl, 1);
    let o = 1 + rl.length; for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }
  class Mqtt {
    constructor(url, onMessage, onStatus) {
      this.url = url; this.onMessage = onMessage; this.onStatus = onStatus;
      this.subs = new Set(); this.up = false; this.closed = false; this.retry = 1000; this.pid = 1; this.buf = new Uint8Array(0);
      this.connect();
    }
    connect() {
      if (this.closed) return;
      let ws;
      try { ws = new WebSocket(this.url, ["mqtt"]); } catch (e) { return this.later(); }
      this.ws = ws; ws.binaryType = "arraybuffer";
      const cid = "somi" + randCode(16).toLowerCase();
      ws.onopen = () => {
        const vh = new Uint8Array([0, 4, 77, 81, 84, 84, 4, 2, 0, 45]); // "MQTT", Level 4, Clean Session, Keepalive 45 s
        ws.send(packet(0x10, vh, str(cid)));
      };
      ws.onmessage = e => this.feed(new Uint8Array(e.data));
      ws.onclose = ws.onerror = () => {
        if (this.ws !== ws) return;
        this.ws = null; clearInterval(this.ping);
        if (this.up) { this.up = false; this.onStatus && this.onStatus(); }
        this.later();
      };
    }
    later() { if (this.closed) return; clearTimeout(this.rt); this.rt = setTimeout(() => this.connect(), this.retry); this.retry = Math.min(15000, this.retry * 1.7); }
    feed(chunk) {
      const b = new Uint8Array(this.buf.length + chunk.length); b.set(this.buf); b.set(chunk, this.buf.length);
      let i = 0;
      while (i + 2 <= b.length) {
        let mult = 1, len = 0, j = i + 1, d;
        do { if (j >= b.length) { this.buf = b.slice(i); return; } d = b[j++]; len += (d & 127) * mult; mult *= 128; } while (d & 128);
        if (j + len > b.length) break;
        this.handle(b[i], b.subarray(j, j + len));
        i = j + len;
      }
      this.buf = b.slice(i);
    }
    handle(h, body) {
      const type = h >> 4;
      if (type === 2) { // CONNACK
        if (body[1] !== 0) { this.ws && this.ws.close(); return; }
        this.up = true; this.retry = 1000;
        for (const t of this.subs) this.sendSub(t);
        clearInterval(this.ping); this.ping = setInterval(() => this.send(new Uint8Array([0xC0, 0])), 25000);
        this.onStatus && this.onStatus();
      } else if (type === 3) { // PUBLISH
        const qos = (h >> 1) & 3, tl = (body[0] << 8) | body[1];
        const topic = td.decode(body.subarray(2, 2 + tl));
        let p = 2 + tl;
        if (qos > 0) {
          const id = body.subarray(p, p + 2); p += 2;
          if (qos === 1) this.send(packet(0x40, id)); // PUBACK
        }
        this.onMessage(topic, body.slice(p));
      }
    }
    send(bytes) { try { if (this.ws && this.ws.readyState === 1) { this.ws.send(bytes); return true; } } catch (e) {} return false; }
    sendSub(t) { const id = this.pid++ & 0xffff || 1; this.send(packet(0x82, new Uint8Array([id >> 8, id & 255]), str(t), new Uint8Array([0]))); }
    subscribe(t) { this.subs.add(t); if (this.up) this.sendSub(t); }
    publish(t, payload, retain) { if (!this.up) return false; return this.send(packet(0x30 | (retain ? 1 : 0), str(t), payload)); }
    close() { this.closed = true; clearTimeout(this.rt); clearInterval(this.ping); if (this.ws) { try { this.send(new Uint8Array([0xE0, 0])); this.ws.close(); } catch (e) {} } this.ws = null; this.up = false; }
  }

  /* Mehrere Relays gemeinsam: abonnieren und senden über alle verbundenen. */
  class Link {
    constructor(onMessage, onStatus) {
      this.onStatus = onStatus;
      this.conns = brokers().map(u => new Mqtt(u, onMessage, () => this.onStatus && this.onStatus(this.status())));
    }
    status() { return { up: this.conns.filter(c => c.up).length, total: this.conns.length }; }
    subscribe(t) { this.conns.forEach(c => c.subscribe(t)); }
    publish(t, payload, retain) { let ok = false; this.conns.forEach(c => { ok = c.publish(t, payload, retain) || ok; }); return ok; }
    close() { this.conns.forEach(c => c.close()); this.onStatus = null; }
  }

  window.SOMI = { ALPHA, randCode, norm, valid, room, personId, token, Link, brokers };
})();
