// server.js - Servidor de Sinalização P2P da Padlock (relay "burro" e endurecido).
//
// O servidor NUNCA vê conteúdo (tudo vai cifrado ponta-a-ponta entre os
// telemóveis). O que ele faz é só: provar quem é quem, encaminhar pacotes e
// guardar temporariamente os que não têm destino online. Modelo de segurança:
//
//  1. AUTENTICAÇÃO OBRIGATÓRIA: o ID de cada utilizador é AUTO-CERTIFICADO -
//     é derivado do hash da sua chave pública Ed25519 (ID = SHA-256(pub)[0..16]).
//     Para se registar com um ID, o cliente tem de assinar um desafio novo
//     (nonce) com a chave privada correspondente. Saber o ID de alguém já NÃO
//     chega para se fazer passar por essa pessoa, nem para lhe tirar a ligação.
//  2. REMETENTE CARIMBADO: o campo senderId de todo o pacote encaminhado é
//     SEMPRE substituído pelo ID autenticado do socket - ninguém pode forjar
//     ordens (apagar conversa, apagar contacto, etc.) em nome de outro.
//  3. LISTA FECHADA de tipos de pacote: tudo o que não estiver na lista é
//     descartado (antes, qualquer tipo desconhecido era reencaminhado).
//  4. LIMITES: tamanho máximo por pacote, ritmo por ligação (token bucket),
//     ligações por IP, pedidos de contacto por hora, e fila de mensagens
//     pendentes com tetos por destino, tetos globais e validade (TTL).
//  5. Credenciais TURN só para ligações autenticadas.
//  6. Zero registos de metadados (não se escrevem IDs nem conteúdos nos logs).
//  7. REMETENTE SELADO: mensagens e ordens seguem em pacotes "sealed" enviados
//     por uma ligação ANÓNIMA (sem registo). O servidor só vê o destino e uma
//     chave de acesso (ak) que só os contactos conhecem; quem enviou vai
//     cifrado dentro do pacote, só o destinatário o consegue abrir.
const http = require('http');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

// ---------------------------------------------------------------- Firebase
// API modular (funciona em todas as versões recentes do firebase-admin; a forma
// antiga "admin.credential" foi removida nas versões novas).
let admin = null; // "admin" passa a ser só o mensageiro FCM (ou null)
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    const { initializeApp, cert } = require('firebase-admin/app');
    const { getMessaging } = require('firebase-admin/messaging');
    initializeApp({ credential: cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)) });
    admin = { messaging: () => getMessaging() };
}

// ------------------------------------------------------------- Configuração
const PORT = process.env.PORT || 8080;
const MAX_PAYLOAD_BYTES = 12 * 1024 * 1024;      // ficheiros até 6MB em base64 + envelope
const AUTH_TIMEOUT_MS = 15 * 1000;               // tem de se autenticar em 15s
const MAX_CONN_PER_IP = 30;
const BUCKET_CAPACITY = 80;                      // rajada máxima de pacotes
const BUCKET_REFILL_PER_SEC = 25;                // ritmo sustentado
const MAX_BYTES_PER_MIN = 80 * 1024 * 1024;      // por ligação
const CONTACT_REQ_PER_HOUR = 20;                 // por ID
const PENDING_TTL_MS = 72 * 60 * 60 * 1000;      // 72h (as mensagens já se autodestroem antes)
const CALL_TTL_MS = 90 * 1000;                   // pacotes de chamada envelhecem depressa
const MAX_PENDING_PER_TARGET = 300;
const MAX_PENDING_BYTES_PER_TARGET = 40 * 1024 * 1024;
const MAX_PENDING_BYTES_TOTAL = 250 * 1024 * 1024;
const MAX_FCM_TOKEN_LEN = 4096;

const ID_REGEX = /^[0-9A-F]{8}(-[0-9A-F]{8}){3}$/;

// Tipos de pacote que se encaminham (sempre por "type") e ações de chamada.
const QUEUEABLE_TYPES = new Set([
    'secure_message', 'secure_file', 'secure_voice',
    'contact_request', 'contact_accepted', 'delete_contact',
    'wipe_chat', 'delete_message', 'update_timer', 'message_read',
]);
const PUSH_TYPES = new Set(['secure_message', 'secure_file', 'secure_voice', 'sealed']);
const SEALED_PER_IP_PER_MIN = 240;
const CALL_ACTIONS = new Set(['call_offer', 'call_answer', 'call_candidate', 'call_ringing', 'call_end']);
// Só estas ações são permitidas a uma ligação "auxiliar" (isolate em segundo
// plano do CallKit, que precisa de avisar "está a tocar"/"recusada").
const AUX_ACTIONS = new Set(['call_ringing', 'call_end']);

// ------------------------------------------------------------------- Estado
const peers = new Map();            // ID -> WebSocket principal autenticado
const akHashes = new Map();         // ID -> SHA-256 da chave de acesso (para pacotes selados)
const sealedPerIp = new Map();      // IP -> [timestamps] (limite de pacotes selados)
const fcmTokens = new Map();        // ID -> token FCM (só definido por quem se autenticou)
const pendingMessages = new Map();  // ID -> [{ data, size, expires }]
let pendingBytesTotal = 0;
const connPerIp = new Map();
const contactReqLog = new Map();    // ID -> [timestamps]
const unacked = new Map();          // sid -> { dest, timer } (pacotes entregues por socket, à espera de confirmação da app)
const ringWait = new Map();         // "quemLiga|quemAtende" -> timer (oferta de chamada à espera de "a tocar")
const ACK_TIMEOUT_MS = 6000;        // sem confirmação em 6s -> fila + push (o socket podia estar "morto")
const RING_ACK_TIMEOUT_MS = 3000;   // sem "a tocar" em 3s -> push FCM a acordar o telemóvel

// ------------------------------------------------------------------ Helpers
function clientIp(req) {
    // O Render acrescenta o IP real do cliente no FIM do X-Forwarded-For (o
    // início pode ser forjado pelo próprio cliente).
    const xff = req.headers['x-forwarded-for'];
    if (xff) {
        const parts = String(xff).split(',').map(s => s.trim()).filter(Boolean);
        if (parts.length) return parts[parts.length - 1];
    }
    return req.socket.remoteAddress || 'unknown';
}

function idFromPublicKey(rawPub) {
    const hex = crypto.createHash('sha256').update(rawPub).digest('hex').slice(0, 32).toUpperCase();
    return `${hex.slice(0, 8)}-${hex.slice(8, 16)}-${hex.slice(16, 24)}-${hex.slice(24, 32)}`;
}

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
function verifyEd25519(rawPub, message, signature) {
    try {
        const key = crypto.createPublicKey({
            key: Buffer.concat([ED25519_SPKI_PREFIX, rawPub]),
            format: 'der',
            type: 'spki',
        });
        return crypto.verify(null, message, key, signature);
    } catch (_) {
        return false;
    }
}

function safeSend(ws, obj) {
    try {
        if (ws.readyState === 1) ws.send(JSON.stringify(obj));
    } catch (_) {}
}

function takeToken(ws, bytes) {
    const now = Date.now();
    const elapsed = (now - ws.bucketAt) / 1000;
    ws.bucketAt = now;
    ws.tokens = Math.min(BUCKET_CAPACITY, ws.tokens + elapsed * BUCKET_REFILL_PER_SEC);
    if (ws.tokens < 1) return false;
    ws.tokens -= 1;
    if (now - ws.minuteStart > 60000) { ws.minuteStart = now; ws.minuteBytes = 0; }
    ws.minuteBytes += bytes;
    return ws.minuteBytes <= MAX_BYTES_PER_MIN;
}

function enqueue(destino, data, ttlMs) {
    const size = Buffer.byteLength(JSON.stringify(data));
    let queue = pendingMessages.get(destino);
    if (!queue) { queue = []; pendingMessages.set(destino, queue); }
    const queueBytes = queue.reduce((s, m) => s + m.size, 0);
    if (queue.length >= MAX_PENDING_PER_TARGET ||
        queueBytes + size > MAX_PENDING_BYTES_PER_TARGET ||
        pendingBytesTotal + size > MAX_PENDING_BYTES_TOTAL) {
        return false; // cheio: descarta em vez de crescer sem limite
    }
    queue.push({ data, size, expires: Date.now() + ttlMs });
    pendingBytesTotal += size;
    return true;
}

function purgeExpired() {
    const now = Date.now();
    for (const [id, queue] of pendingMessages) {
        const keep = [];
        for (const m of queue) {
            if (m.expires > now) keep.push(m); else pendingBytesTotal -= m.size;
        }
        if (keep.length) pendingMessages.set(id, keep); else pendingMessages.delete(id);
    }
    for (const [ip, arr] of sealedPerIp) {
        const recent = arr.filter(t => now - t < 60000);
        if (recent.length) sealedPerIp.set(ip, recent); else sealedPerIp.delete(ip);
    }
    for (const [id, arr] of contactReqLog) {
        const recent = arr.filter(t => now - t < 3600000);
        if (recent.length) contactReqLog.set(id, recent); else contactReqLog.delete(id);
    }
}
setInterval(purgeExpired, 60 * 1000).unref();

// Guarda o pacote e acorda o telemóvel por FCM (só ação, sem conteúdo).
function queueAndNotify(data, destino, isCallPacket) {
    const ttl = isCallPacket ? CALL_TTL_MS : PENDING_TTL_MS;
    const queued = enqueue(destino, data, ttl);

    const tokenFCM = fcmTokens.get(destino);
    if (!admin || !tokenFCM) return queued;

    const isCall = data.action === 'call_offer';
    const isMessage = PUSH_TYPES.has(data.type);
    const isCallEnd = data.action === 'call_end';
    if (!(isCall || isMessage || isCallEnd)) return queued;

    const fcmData = isCall
        ? {
            action: 'call_offer',
            senderId: String(data.senderId || ''),
            sdp: JSON.stringify(data.sdp),
            isVideo: data.isVideo ? 'true' : 'false',
            ts: String(data.timestamp || ''),
            sig: String(data.sig || ''),
        }
        : isCallEnd
        ? { action: 'call_end' }
        : { action: 'secure_message' };

    admin.messaging().send({ token: tokenFCM, data: fcmData, android: { priority: 'high' } })
        .catch((e) => { console.error('[FCM] falha ao enviar push:', (e && (e.code || e.message)) || 'erro'); }); // só o código do erro - nunca IDs
    return queued;
}

// Entrega por socket COM confirmação da app. Um socket pode parecer vivo (o
// telemóvel adormeceu, a rede mudou) e engolir o pacote sem erro nenhum: a
// primeira mensagem perdia-se e só a seguinte dava erro. Agora a app confirma
// cada pacote (ack); sem confirmação em 6s, vai para a fila e acorda o
// telemóvel por push.
function deliverTracked(targetSocket, dest, packet, done) {
    const sid = crypto.randomBytes(8).toString('hex');
    const wire = packet.type ? { type: packet.type, sid, ...packet } : packet;
    const timer = setTimeout(() => {
        if (unacked.delete(sid)) queueAndNotify(packet, dest, false);
    }, ACK_TIMEOUT_MS);
    unacked.set(sid, { dest, timer });
    targetSocket.send(JSON.stringify(wire), (err) => {
        if (err) {
            clearTimeout(timer);
            unacked.delete(sid);
            peers.delete(dest);
            if (done) done(queueAndNotify(packet, dest, false));
        } else if (done) {
            done(true);
        }
    });
}

// Credenciais TURN (metered.ca) vêm de variáveis de ambiente no Render,
// nunca ficam escritas no código do cliente.
function buildIceServers() {
    return [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun.relay.metered.ca:80' },
        { urls: 'turn:global.relay.metered.ca:80', username: process.env.TURN_USERNAME, credential: process.env.TURN_CREDENTIAL },
        { urls: 'turn:global.relay.metered.ca:80?transport=tcp', username: process.env.TURN_USERNAME, credential: process.env.TURN_CREDENTIAL },
        { urls: 'turn:global.relay.metered.ca:443', username: process.env.TURN_USERNAME, credential: process.env.TURN_CREDENTIAL },
        { urls: 'turns:global.relay.metered.ca:443?transport=tcp', username: process.env.TURN_USERNAME, credential: process.env.TURN_CREDENTIAL },
    ];
}

// --------------------------------------------------------------- HTTP / WS
const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('OK');
});

const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_PAYLOAD_BYTES });

server.on('upgrade', (request, socket, head) => {
    const ip = clientIp(request);
    const n = connPerIp.get(ip) || 0;
    if (n >= MAX_CONN_PER_IP) {
        socket.write('HTTP/1.1 429 Too Many Requests\r\n\r\n');
        socket.destroy();
        return;
    }
    wss.handleUpgrade(request, socket, head, (ws) => {
        ws.clientIp = ip;
        connPerIp.set(ip, n + 1);
        wss.emit('connection', ws, request);
    });
});

// Batimento: de 20 em 20s manda um ping a cada ligação; quem não responder
// até ao ciclo seguinte é considerado morto e cortado (antes, telemóveis que
// adormeciam ficavam "online" para sempre e engoliam mensagens).
const heartbeat = setInterval(() => {
    for (const client of wss.clients) {
        if (client.isAlive === false) { try { client.terminate(); } catch (_) {} continue; }
        client.isAlive = false;
        try { client.ping(); } catch (_) {}
    }
}, 20 * 1000);
heartbeat.unref();

wss.on('connection', (ws) => {
    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });
    ws.authedId = null;
    ws.isAux = false;
    ws.nonce = crypto.randomBytes(32).toString('hex');
    ws.tokens = BUCKET_CAPACITY;
    ws.bucketAt = Date.now();
    ws.minuteStart = Date.now();
    ws.minuteBytes = 0;
    ws.violations = 0;

    safeSend(ws, { type: 'challenge', nonce: ws.nonce });

    const authTimer = setTimeout(() => {
        if (!ws.authedId) { try { ws.close(4008, 'auth_timeout'); } catch (_) {} }
    }, AUTH_TIMEOUT_MS);

    const violation = () => {
        ws.violations += 1;
        if (ws.violations > 10) { try { ws.close(4009, 'abuse'); } catch (_) {} }
    };

    ws.on('message', (message, isBinary) => {
        if (isBinary) { violation(); return; }
        const raw = message.toString();
        if (!takeToken(ws, raw.length)) { violation(); return; }

        let data;
        try { data = JSON.parse(raw); } catch (_) { violation(); return; }
        if (!data || typeof data !== 'object' || Array.isArray(data)) { violation(); return; }

        // ------------------------------------------------ Registo / login
        if (data.type === 'register') {
            // Já autenticado: só serve para atualizar o token FCM do PRÓPRIO ID.
            if (ws.authedId) {
                if (!ws.isAux && typeof data.fcmToken === 'string' && data.fcmToken.length > 0 &&
                    data.fcmToken.length <= MAX_FCM_TOKEN_LEN &&
                    (data.senderId === undefined || data.senderId === ws.authedId)) {
                    fcmTokens.set(ws.authedId, data.fcmToken);
                }
                return;
            }
            const id = data.senderId;
            if (typeof id !== 'string' || !ID_REGEX.test(id) ||
                typeof data.authPub !== 'string' || typeof data.sig !== 'string') {
                safeSend(ws, { type: 'error', code: 'bad_register' }); violation(); return;
            }
            let pub, sig;
            try { pub = Buffer.from(data.authPub, 'base64'); sig = Buffer.from(data.sig, 'base64'); } catch (_) { violation(); return; }
            if (pub.length !== 32 || sig.length !== 64 || idFromPublicKey(pub) !== id) {
                safeSend(ws, { type: 'error', code: 'id_mismatch' }); violation(); return;
            }
            const msg = Buffer.from(`padlock-auth-v1|${ws.nonce}|${id}|${data.aux === true ? 'aux' : 'main'}`, 'utf8');
            if (!verifyEd25519(pub, msg, sig)) {
                safeSend(ws, { type: 'error', code: 'bad_signature' }); violation(); return;
            }

            clearTimeout(authTimer);
            ws.authedId = id;
            ws.isAux = data.aux === true;

            if (!ws.isAux) {
                if (typeof data.akHash === 'string') {
                    try {
                        const h = Buffer.from(data.akHash, 'base64');
                        if (h.length === 32) akHashes.set(id, h);
                    } catch (_) {}
                }
                // A ligação principal anterior deste MESMO dono é substituída
                // (só quem tem a chave privada chega aqui).
                const old = peers.get(id);
                if (old && old !== ws) { try { old.close(4001, 'replaced'); } catch (_) {} }
                peers.set(id, ws);
                if (typeof data.fcmToken === 'string' && data.fcmToken.length > 0 && data.fcmToken.length <= MAX_FCM_TOKEN_LEN) {
                    fcmTokens.set(id, data.fcmToken);
                }
            }
            safeSend(ws, { type: 'registered', aux: ws.isAux });

            if (!ws.isAux && pendingMessages.has(id)) {
                const queue = pendingMessages.get(id);
                pendingMessages.delete(id);
                const now = Date.now();
                let i = 0;
                for (const m of queue) {
                    pendingBytesTotal -= m.size;
                    if (m.expires <= now) continue;
                    setTimeout(() => {
                        const cur = peers.get(id);
                        if (cur && cur.readyState === 1) safeSend(cur, m.data);
                    }, (i++) * 100);
                }
            }
            return;
        }

        if (data.type === 'ping') { safeSend(ws, { type: 'pong' }); return; }

        // ------------------- Ligação ANÓNIMA: só serve para pacotes selados
        if (data.type === 'anon_hello' && !ws.authedId) {
            ws.isAnon = true;
            clearTimeout(authTimer);
            return;
        }
        if (data.type === 'sealed') {
            const dest = data.targetId;
            const mid = (typeof data.mid === 'string' && data.mid.length <= 64) ? data.mid : null;
            // Confirmação de receção ao remetente anónimo: "ok" = entregue ou
            // guardado na fila; "false" = recusado. (Só diz isto a quem já
            // conhece a chave de acesso; não revela mais nada.)
            const ack = (ok) => { if (mid) safeSend(ws, { type: 'sealed_ack', mid, ok }); };
            if (typeof dest !== 'string' || !ID_REGEX.test(dest) ||
                typeof data.ak !== 'string' || typeof data.blob !== 'string') { ack(false); return; }
            // limite por IP (não há identidade a limitar)
            const nowMs = Date.now();
            const arr = (sealedPerIp.get(ws.clientIp) || []).filter(t => nowMs - t < 60000);
            if (arr.length >= SEALED_PER_IP_PER_MIN) { ack(false); return; }
            arr.push(nowMs);
            sealedPerIp.set(ws.clientIp, arr);
            // A chave de acesso tem de ser a do destinatário (só os contactos a têm).
            let good = false;
            try {
                const expected = akHashes.get(dest);
                const given = crypto.createHash('sha256').update(Buffer.from(data.ak, 'base64')).digest();
                good = !!expected && expected.length === given.length && crypto.timingSafeEqual(expected, given);
            } catch (_) { good = false; }
            if (!good) { ack(false); return; } // sem pistas sobre quem existe
            const out = { type: 'sealed', blob: data.blob };
            const targetSocket = peers.get(dest);
            if (targetSocket && targetSocket.readyState === 1) {
                deliverTracked(targetSocket, dest, out, ack);
            } else {
                if (targetSocket) peers.delete(dest);
                ack(queueAndNotify(out, dest, false));
            }
            return;
        }

        // ------------------------------- Daqui para baixo: só autenticados
        if (!ws.authedId) {
            safeSend(ws, { type: 'error', code: 'auth_required' });
            violation();
            return;
        }

        // Confirmação de receção enviada pela app do destinatário.
        if (data.type === 'ack') {
            const e = typeof data.sid === 'string' ? unacked.get(data.sid) : null;
            if (e && e.dest === ws.authedId) { clearTimeout(e.timer); unacked.delete(data.sid); }
            return;
        }

        if (data.type === 'get_ice_servers') {
            if (ws.isAux) return;
            safeSend(ws, { type: 'ice_servers', iceServers: buildIceServers() });
            return;
        }

        const rawDest = data.targetId !== undefined ? data.targetId : data.target;
        const isCallPacket = typeof data.action === 'string' && CALL_ACTIONS.has(data.action);

        if (data.type === 'check_status') {
            if (ws.isAux || typeof rawDest !== 'string' || !ID_REGEX.test(rawDest)) return; // ID inválido: ignora sem penalizar
            const alvo = peers.get(rawDest);
            safeSend(ws, {
                type: 'peer_status',
                targetId: rawDest,
                status: (alvo && alvo.readyState === 1) ? 'Online' : 'Offline',
            });
            return;
        }

        // Lista fechada: ou é um tipo conhecido, ou é uma ação de chamada.
        const isQueueableType = typeof data.type === 'string' && QUEUEABLE_TYPES.has(data.type);
        if (!isQueueableType && !isCallPacket) { violation(); return; }
        if (ws.isAux && !(isCallPacket && AUX_ACTIONS.has(data.action))) { violation(); return; }
        if (typeof rawDest !== 'string' || !ID_REGEX.test(rawDest)) return; // destino inválido: descarta sem penalizar
        if (rawDest === ws.authedId && !isCallPacket) { return; } // ninguém precisa de escrever a si próprio

        if (data.type === 'contact_request') {
            const now = Date.now();
            const arr = (contactReqLog.get(ws.authedId) || []).filter(t => now - t < 3600000);
            if (arr.length >= CONTACT_REQ_PER_HOUR) {
                safeSend(ws, { type: 'error', code: 'rate_limited' });
                return;
            }
            arr.push(now);
            contactReqLog.set(ws.authedId, arr);
        }

        // Pacote de saída reconstruído: o remetente é SEMPRE o autenticado.
        data.senderId = ws.authedId;
        data.targetId = rawDest;
        delete data.target;

        // "A tocar" / resposta / fim de chamada: a oferta já foi tratada - cancela
        // o push de reserva (nos dois sentidos).
        if (data.action === 'call_ringing' || data.action === 'call_answer' || data.action === 'call_end') {
            for (const key of [`${rawDest}|${ws.authedId}`, `${ws.authedId}|${rawDest}`]) {
                if (ringWait.has(key)) { clearTimeout(ringWait.get(key)); ringWait.delete(key); }
            }
        }

        // Pacotes de chamada que têm de sobreviver a um destinatário ainda
        // offline (a atender fora da app): a oferta, o fim, e os CANDIDATOS ICE
        // e a resposta (sem os candidatos de quem liga, a chamada atendida
        // fora da app ficava presa em "Exchanging Encryption Keys").
        const wantsQueue = isQueueableType || data.action === 'call_offer' || data.action === 'call_end' ||
            data.action === 'call_candidate' || data.action === 'call_answer';

        const targetSocket = peers.get(rawDest);
        if (targetSocket && targetSocket.readyState === 1) {
            if (isQueueableType) {
                deliverTracked(targetSocket, rawDest, data, null);
            } else {
                targetSocket.send(JSON.stringify(data), (err) => {
                    if (err) {
                        peers.delete(rawDest);
                        if (wantsQueue) queueAndNotify(data, rawDest, true);
                    }
                });
                if (data.action === 'call_offer') {
                    // Se o telemóvel não disser "a tocar" em 3s, o socket estava
                    // morto/adormecido: fila + push a acordá-lo.
                    const key = `${ws.authedId}|${rawDest}`;
                    if (ringWait.has(key)) clearTimeout(ringWait.get(key));
                    ringWait.set(key, setTimeout(() => {
                        ringWait.delete(key);
                        queueAndNotify(data, rawDest, true);
                    }, RING_ACK_TIMEOUT_MS));
                }
            }
        } else {
            if (targetSocket) peers.delete(rawDest);
            if (wantsQueue) queueAndNotify(data, rawDest, isCallPacket);
        }
    });

    ws.on('close', () => {
        clearTimeout(authTimer);
        const n = (connPerIp.get(ws.clientIp) || 1) - 1;
        if (n <= 0) connPerIp.delete(ws.clientIp); else connPerIp.set(ws.clientIp, n);
        if (ws.authedId && !ws.isAux && peers.get(ws.authedId) === ws) peers.delete(ws.authedId);
        // (a chave de acesso fica: é reenviada a cada registo)
    });

    ws.on('error', () => {});
});

server.listen(PORT, () => {
    console.log('SERVIDOR PADLOCK P2P ATIVO (modo autenticado)');
});
