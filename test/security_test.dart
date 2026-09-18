import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:hive/hive.dart';
import 'package:cryptography/cryptography.dart' as crypto;

import 'package:a_minha_app/main.dart';

void main() {
  group('controlo e chamadas', controlTests);
  late Directory dir;

  setUp(() async {
    dir = await Directory.systemTemp.createTemp('padlock_test');
    Hive.init(dir.path);
  });

  tearDown(() async {
    await Hive.close();
    try {
      await dir.delete(recursive: true);
    } catch (_) {}
  });

  test('AES-GCM Hive cipher: guarda, reabre e devolve os mesmos dados', () async {
    final key = Uint8List.fromList(List<int>.generate(32, (i) => i));
    var box = await Hive.openBox('t1', encryptionCipher: AesGcmHiveCipher(key));
    await box.put('a', 'olá mundo');
    await box.put('big', jsonEncode(List<int>.generate(5000, (i) => i)));
    await box.put('n', 12345);
    await box.close();

    box = await Hive.openBox('t1', encryptionCipher: AesGcmHiveCipher(key));
    expect(box.get('a'), 'olá mundo');
    expect(jsonDecode(box.get('big')).length, 5000);
    expect(box.get('n'), 12345);
    await box.close();
  });

  test('AES-GCM Hive cipher: chave errada é recusada', () async {
    final key = Uint8List.fromList(List<int>.generate(32, (i) => i));
    final wrong = Uint8List.fromList(List<int>.generate(32, (i) => 255 - i));
    final box = await Hive.openBox('t2', encryptionCipher: AesGcmHiveCipher(key));
    await box.put('a', 'segredo');
    await box.close();
    // O Hive nunca "devolve lixo" com a chave errada (a app também só abre o
    // cofre depois de validar a chave por hash, ver PadlockVaultKey).
    bool readable = false;
    try {
      final b = await Hive.openBox('t2', encryptionCipher: AesGcmHiveCipher(wrong));
      readable = b.get('a') == 'segredo';
    } catch (_) {}
    expect(readable, isFalse);
  });

  test('AES-GCM Hive cipher: ficheiro adulterado é detetado', () async {
    final key = Uint8List.fromList(List<int>.generate(32, (i) => i));
    var box = await Hive.openBox('t3', encryptionCipher: AesGcmHiveCipher(key));
    await box.put('a', 'texto importante que ninguém pode alterar');
    final path = box.path!;
    await box.close();

    final file = File(path);
    final bytes = await file.readAsBytes();
    bytes[bytes.length - 20] ^= 0x01; // vira um bit no meio da cifra
    await file.writeAsBytes(bytes);

    bool detected = false;
    try {
      box = await Hive.openBox('t3', encryptionCipher: AesGcmHiveCipher(key));
      final v = box.get('a');
      if (v != 'texto importante que ninguém pode alterar') detected = true;
    } catch (_) {
      detected = true;
    }
    expect(detected, isTrue);
  });

  test('Argon2id v2 (64 MiB) e v1 dão chaves diferentes e estáveis', () async {
    final salt = Uint8List.fromList(List<int>.filled(16, 9));
    final v1a = await PadlockVaultKey.deriveKey('uma frase forte de teste', salt, version: 1);
    final v1b = await PadlockVaultKey.deriveKey('uma frase forte de teste', salt, version: 1);
    final v2 = await PadlockVaultKey.deriveKey('uma frase forte de teste', salt, version: 2);
    expect(v1a, v1b);
    expect(v1a, isNot(v2));
    expect(v2.length, 32);
  });

  test('ID derivado da chave pública é auto-certificado e formato estável', () async {
    final pub = Uint8List.fromList(List<int>.generate(32, (i) => i * 3));
    final id = await PadlockIdentity.idFromPublicKey(pub);
    expect(RegExp(r'^[0-9A-F]{8}(-[0-9A-F]{8}){3}$').hasMatch(id), isTrue);
    expect(await PadlockIdentity.idFromPublicKey(pub), id);
  });
}

// ---- Mensagens de controlo autenticadas (PadlockCtrl) ----
void controlTests() {
  late Directory dir;
  late Box box;
  const idA = 'AAAAAAAA-AAAAAAAA-AAAAAAAA-AAAAAAAA';
  const idB = 'BBBBBBBB-BBBBBBBB-BBBBBBBB-BBBBBBBB';
  final ctrlKey = base64Encode(List<int>.generate(32, (i) => i + 1));

  setUp(() async {
    dir = await Directory.systemTemp.createTemp('padlock_ctrl');
    Hive.init(dir.path);
    box = await Hive.openBox('padlock_vault');
  });
  tearDown(() async {
    await Hive.close();
    try {
      await dir.delete(recursive: true);
    } catch (_) {}
  });

  Future<Map<String, dynamic>> asA(String type, {Map<String, dynamic> fields = const {}}) async {
    await box.put('user_privacy_id', idA);
    await box.put('ctrl_key_$idB', ctrlKey);
    return (await PadlockCtrl.build(idB, type, fields: fields))!;
  }

  Future<void> asB({String? key}) async {
    await box.put('user_privacy_id', idB);
    await box.put('ctrl_key_$idA', key ?? ctrlKey);
  }

  test('MAC de controlo: pacote legítimo é aceite', () async {
    final pkt = await asA('wipe_chat');
    await asB();
    expect(await PadlockCtrl.verify(pkt), isTrue);
  });

  test('MAC de controlo: campo alterado (timestamp da mensagem a apagar) é recusado', () async {
    final pkt = await asA('delete_message', fields: {'timestamp': 111});
    pkt['timestamp'] = 222; // servidor malicioso troca a mensagem alvo
    await asB();
    expect(await PadlockCtrl.verify(pkt), isFalse);
  });

  test('MAC de controlo: tipo trocado (message_read -> wipe_chat) é recusado', () async {
    final pkt = await asA('message_read');
    pkt['type'] = 'wipe_chat';
    await asB();
    expect(await PadlockCtrl.verify(pkt), isFalse);
  });

  test('MAC de controlo: remetente forjado / chave errada é recusado', () async {
    final pkt = await asA('wipe_chat');
    await asB(key: base64Encode(List<int>.generate(32, (i) => 200 - i)));
    expect(await PadlockCtrl.verify(pkt), isFalse);
  });

  test('MAC de controlo: repetição (replay) é recusada à 3ª utilização', () async {
    final pkt = await asA('wipe_chat');
    await asB();
    expect(await PadlockCtrl.verify(pkt), isTrue); // ecrã principal
    expect(await PadlockCtrl.verify(pkt), isTrue); // chat aberto
    expect(await PadlockCtrl.verify(pkt), isFalse); // repetição
  });

  test('MAC de controlo: pacote antigo (>4 dias) é recusado', () async {
    final pkt = await asA('wipe_chat');
    pkt['ts'] = DateTime.now().millisecondsSinceEpoch - 5 * 24 * 3600 * 1000;
    await asB();
    expect(await PadlockCtrl.verify(pkt), isFalse);
  });

  test('Assinatura de chamada: oferta trocada ou de outro contacto não valida', () async {
    final kp = await crypto.Ed25519().newKeyPair();
    final pub = base64Encode((await kp.extractPublicKey()).bytes);
    final msg = await callSigMessage('offer', idA, idB, 1000, 'v=0 sdp-original', isVideo: false);
    final sig = base64Encode((await crypto.Ed25519().sign(msg, keyPair: kp)).bytes);
    Future<bool> check(List<int> m) => PadlockIdentity.verify(pubB64: pub, message: m, sigB64: sig);
    expect(await check(msg), isTrue);
    expect(await check(await callSigMessage('offer', idA, idB, 1000, 'v=0 sdp-TROCADO', isVideo: false)), isFalse);
    expect(await check(await callSigMessage('offer', idA, idB, 1000, 'v=0 sdp-original', isVideo: true)), isFalse);
    expect(await check(await callSigMessage('offer', idB, idA, 1000, 'v=0 sdp-original', isVideo: false)), isFalse);
    expect(await check(await callSigMessage('answer', idA, idB, 1000, 'v=0 sdp-original', isVideo: false)), isFalse);
  });
}
