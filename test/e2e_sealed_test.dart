// Teste de ponta a ponta: servidor REAL (node) + código de selagem da app.
// Só corre se PADLOCK_SERVER_DIR apontar para uma pasta com o servidor e
// node_modules (senão é ignorado).
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:cryptography/cryptography.dart' as crypto;
import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';

import 'package:a_minha_app/main.dart';

class _Client {
  final WebSocket ws;
  final List<Map<String, dynamic>> msgs = [];
  String? nonce;
  _Client(this.ws) {
    ws.listen((m) {
      final d = jsonDecode(m as String) as Map<String, dynamic>;
      msgs.add(d);
      if (d['type'] == 'challenge') nonce = d['nonce'] as String;
    });
  }
}

Future<_Client> _connect(int port) async {
  final ws = await WebSocket.connect('ws://localhost:$port');
  final c = _Client(ws);
  await Future.delayed(const Duration(milliseconds: 200));
  return c;
}

void main() {
  final serverDir = Platform.environment['PADLOCK_SERVER_DIR'];
  test('Selado ponta a ponta: A (anónimo) -> servidor real -> B abre e sabe que foi A', () async {
    const port = 19123;
    final proc = await Process.start('node', ['server.js'], workingDirectory: serverDir, environment: {'PORT': '$port'});
    await Future.delayed(const Duration(milliseconds: 1000));
    final dir = await Directory.systemTemp.createTemp('padlock_e2e');
    Hive.init(dir.path);
    try {
      // identidades reais (mesmo código da app)
      final edA = crypto.Ed25519();
      final kpA = await edA.newKeyPair();
      final pubA = (await kpA.extractPublicKey()).bytes;
      final idA = await PadlockIdentity.idFromPublicKey(pubA);
      final kpB = await edA.newKeyPair();
      final pubB = (await kpB.extractPublicKey()).bytes;
      final idB = await PadlockIdentity.idFromPublicKey(pubB);
      final akB = List<int>.generate(32, (i) => (i * 5 + 1) % 256);
      final akHashB = base64Encode((await crypto.Sha256().hash(akB)).bytes);
      final ctrl = base64Encode(List<int>.generate(32, (i) => i + 9));

      // B liga e regista-se (autenticado, com a sua chave de acesso)
      final b = await _connect(port);
      final sig = await edA.sign(utf8.encode('padlock-auth-v1|${b.nonce}|$idB|main'), keyPair: kpB);
      b.ws.add(jsonEncode({
        'type': 'register',
        'senderId': idB,
        'authPub': base64Encode(pubB),
        'sig': base64Encode(sig.bytes),
        'akHash': akHashB,
      }));
      await Future.delayed(const Duration(milliseconds: 300));
      expect(b.msgs.any((m) => m['type'] == 'registered'), isTrue);

      // A: ligação ANÓNIMA, sem nunca se registar
      final a = await _connect(port);
      a.ws.add(jsonEncode({'type': 'anon_hello'}));
      final blob = await PadlockSeal.seal(ctrl, {
        'type': 'secure_message',
        'senderId': idA,
        'targetId': idB,
        'payload': 'cifrado-ratchet',
        'chainIndex': 0,
        'dh': '',
        'timestamp': 1,
      });
      a.ws.add(jsonEncode({'type': 'sealed', 'targetId': idB, 'ak': base64Encode(akB), 'blob': blob}));
      await Future.delayed(const Duration(milliseconds: 400));

      final got = b.msgs.where((m) => m['type'] == 'sealed').toList();
      expect(got.length, 1);
      expect(got.first.containsKey('senderId'), isFalse); // o servidor não sabe quem enviou

      // B abre com a chave do contacto A
      final box = await Hive.openBox('padlock_vault');
      await box.put('user_privacy_id', idB);
      await box.put('ctrl_key_$idA', ctrl);
      final opened = await PadlockSeal.open(got.first['blob'] as String);
      expect(opened, isNotNull);
      expect(opened!['senderId'], idA);
      expect(opened['payload'], 'cifrado-ratchet');

      await a.ws.close();
      await b.ws.close();
    } finally {
      await Hive.close();
      proc.kill();
      try {
        await dir.delete(recursive: true);
      } catch (_) {}
    }
  }, skip: serverDir == null ? 'defina PADLOCK_SERVER_DIR' : false);
}
