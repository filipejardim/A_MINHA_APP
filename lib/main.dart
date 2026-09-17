import 'dart:async';
import 'dart:typed_data';
import 'package:hive_flutter/hive_flutter.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:encrypt/encrypt.dart' as enc;
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:flutter_callkit_incoming/flutter_callkit_incoming.dart';
import 'package:flutter_callkit_incoming/entities/entities.dart';
import 'dart:math';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:web_socket_channel/web_socket_channel.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';

// --- NOVAS FERRAMENTAS DE DADOS ---

import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import 'dart:convert';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_messaging/firebase_messaging.dart';

import 'package:audioplayers/audioplayers.dart';
import 'package:wakelock_plus/wakelock_plus.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:image_picker/image_picker.dart';
import 'package:file_picker/file_picker.dart';
import 'package:record/record.dart';
import 'package:in_app_purchase/in_app_purchase.dart';
import 'package:bip39_mnemonic/bip39_mnemonic.dart' as bip39;
import 'package:bip32/bip32.dart' as bip32;
import 'package:web3dart/web3dart.dart';
import 'package:http/http.dart' as http;
import 'package:share_plus/share_plus.dart';
import 'package:path_provider/path_provider.dart';
import 'dart:io';
// Serviço de rede para conectar ao servidor
class PadlockNetwork {
  static String? chatAbertoAtualmente;
  static bool _emChamada = false;
  static DateTime? _emChamadaSetAt;

  // "Em chamada" nunca pode ficar preso a 'true' para sempre - se a app
  // morrer a meio de uma chamada sem correr o código que a desliga
  // corretamente, esta flag ficava presa e bloqueava QUALQUER chamada nova
  // (incluindo aceitar via CallKit) até reiniciares a app por completo.
  // Passado um tempo mais do que suficiente para qualquer chamada real
  // tocar e ligar, trata-se como uma flag esquecida e destranca sozinha.
  static bool get emChamada {
    if (_emChamada && _emChamadaSetAt != null &&
        DateTime.now().difference(_emChamadaSetAt!) > const Duration(seconds: 90)) {
      _emChamada = false;
    }
    return _emChamada;
  }

  static set emChamada(bool value) {
    _emChamada = value;
    _emChamadaSetAt = value ? DateTime.now() : null;
  }
  static bool isUnlocked = false;
  static String? pendingFcmToken;
  // Guarda partilhada entre TODOS os temporizadores de bloqueio automático
  // (sessão principal aos 15 min, Vault Files e Crypto Vault aos 5 min cada
  // um por si). Sem isto, dois destes podiam disparar quase ao mesmo tempo
  // e mexer no MESMO Navigator em simultâneo (um a fechar tudo até à
  // primeira rota, outro a substituir essa mesma rota pelo LoginScreen) -
  // essa corrida é a explicação mais provável para o ecrã branco preso,
  // exigindo fechar a app à força.
  static bool isPerformingAutoLock = false;

  static Map<String, dynamic>? pendingCallData;
  static WebSocketChannel? channel;
  static final StreamController<dynamic> messageHub = StreamController<dynamic>.broadcast();
  static ValueNotifier<String> status = ValueNotifier<String>('Offline');
static final List<dynamic> earlyCandidates = [];
  // Inicializa o detetor de hardware (Net do telemóvel)
  static void initNetworkListener() {
    status.value = 'Online';
    connect();
  }
  static void disconnect() {
    channel?.sink.close();
    channel = null;
  }

  static void connect() {
    // Só tenta abrir o tubo P2P se o telemóvel tiver net real
    //if (html.window.navigator.onLine != true) return;
    if (channel != null) return;

    try {
      channel = WebSocketChannel.connect(Uri.parse('wss://servidor-padlock.onrender.com'));
      channel?.stream.listen(
        (data) => messageHub.add(data),
        onDone: () => channel = null,
        onError: (e) => channel = null,
      );
    } catch (e) {
      channel = null;
    }
  }
}

// Mostra a chamada como uma camada persistente por cima de toda a app
// (Overlay do Flutter), em vez de uma rota normal do Navigator. Antes, o
// ActiveCallScreen era uma rota como outra qualquer - um simples toque no
// botão de voltar do Android destruía a chamada por completo (fechava a
// ligação com o outro lado sem aviso nenhum: "o outro lado ficava em
// Connecting... com o Morse a tocar sem parar"). Agora a chamada nunca é
// destruída por navegar para outro lado - fica minimizada numa bolha
// pequena, e só termina de verdade ao carregar no botão vermelho de
// desligar. `minimized` é a única fonte de verdade: o ActiveCallScreen lê-a
// para decidir se mostra o ecrã inteiro ou a bolha, e o botão de voltar do
// Android (ver _PadlockAppState.didPopRoute) escreve nela em vez de fechar
// a app ou voltar ao ecrã anterior.
class PadlockCallOverlay {
  static OverlayEntry? _entry;
  static final ValueNotifier<bool> minimized = ValueNotifier(false);

  static bool get isActive => _entry != null;

  static void show(Widget screen) {
    hide();
    final overlayState = navigatorKey.currentState?.overlay;
    if (overlayState == null) return;
    minimized.value = false;
    _entry = OverlayEntry(builder: (context) => screen);
    overlayState.insert(_entry!);
  }

  static void hide() {
    _entry?.remove();
    _entry = null;
    minimized.value = false;
  }
}

// Chave do cofre derivada da frase de encriptação escolhida pelo utilizador
// (Argon2id), ao estilo VeraCrypt: sem a frase certa, os dados ficam
// matematicamente ilegíveis mesmo com o telemóvel fisicamente comprometido
// (Keystore extraído, imagem forense, etc). A app nunca guarda a frase nem
// a chave derivada em disco - só um sal público (não secreto) que serve
// para repetir a mesma derivação em cada arranque.
class PadlockVaultKey {
  static const String _saltPrefsKey = 'padlock_vault_salt';

  static Future<bool> hasVault() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_saltPrefsKey) != null;
  }

  static Future<Uint8List> createSalt() async {
    final random = Random.secure();
    final salt = Uint8List.fromList(List<int>.generate(16, (_) => random.nextInt(256)));
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_saltPrefsKey, base64Encode(salt));
    return salt;
  }

  static Future<Uint8List?> getSalt() async {
    final prefs = await SharedPreferences.getInstance();
    final saltBase64 = prefs.getString(_saltPrefsKey);
    if (saltBase64 == null) return null;
    return base64Decode(saltBase64);
  }

  static Future<void> wipe() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_saltPrefsKey);
  }

  // Verificação da frase FORA do Hive, antes de sequer o tocar.
  // Descoberta importante: a cifra do Hive não é autenticada, e abri-lo com
  // uma chave errada por vezes deixa a caixa presa num estado estranho -
  // reportado como "depois de errar uma vez, a chave CERTA também passa a
  // ser recusada, só resolve reinstalando". Ao verificar a frase com um
  // hash simples em SharedPreferences ANTES de chamar Hive.openBox, nunca
  // mais se chama openBox com uma chave errada - o Hive nunca fica nesse
  // estado, porque só o vemos com a chave já confirmada como certa.
  static Future<void> storeKeyHash(String hashPrefsKey, Uint8List derivedKey) async {
    final digest = await crypto.Sha256().hash(derivedKey);
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(hashPrefsKey, base64Encode(digest.bytes));
  }

  static Future<bool> verifyKeyHash(String hashPrefsKey, Uint8List derivedKey) async {
    final prefs = await SharedPreferences.getInstance();
    final stored = prefs.getString(hashPrefsKey);
    if (stored == null) return false;
    final digest = await crypto.Sha256().hash(derivedKey);
    return base64Encode(digest.bytes) == stored;
  }

  static Future<void> wipeKeyHash(String hashPrefsKey) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(hashPrefsKey);
  }

  static Future<Uint8List> deriveKey(String passphrase, Uint8List salt) async {
    final algorithm = crypto.Argon2id(
      parallelism: 1,
      memory: 19456, // ~19 MiB, mínimo recomendado pela OWASP para Argon2id
      iterations: 3,
      hashLength: 32,
    );
    final secretKey = await algorithm.deriveKeyFromPassword(
      password: passphrase,
      nonce: salt,
    );
    final bytes = await secretKey.extractBytes();
    return Uint8List.fromList(bytes);
  }
}

// Compra dentro da app via Google Play Billing - é o ÚNICO método de
// pagamento que a Play Store permite para desbloquear conteúdo digital
// dentro de uma app (usar PayPal ou uma carteira cripto para isto viola as
// regras da loja e é motivo de remoção). Os IDs abaixo têm de corresponder
// EXATAMENTE aos produtos de subscrição criados na Google Play Console -
// sem isso, queryProductDetails devolve uma lista vazia e a compra falha.
class PremiumService {
  static const String monthlyProductId = 'padlock_premium_monthly';
  static const String yearlyProductId = 'padlock_premium_yearly';

  static StreamSubscription<List<PurchaseDetails>>? _subscription;

  static bool get isPremium =>
      Hive.box('padlock_vault').get('is_premium', defaultValue: false) == true;

  static void init() {
    _subscription?.cancel();
    _subscription = InAppPurchase.instance.purchaseStream.listen((purchases) {
      for (final purchase in purchases) {
        if (purchase.status == PurchaseStatus.purchased || purchase.status == PurchaseStatus.restored) {
          Hive.box('padlock_vault').put('is_premium', true);
        } else if (purchase.status == PurchaseStatus.error) {
          print('Erro na compra Premium: ${purchase.error}');
        }
        if (purchase.pendingCompletePurchase) {
          InAppPurchase.instance.completePurchase(purchase);
        }
      }
    }, onError: (e) => print('Erro no stream de compras: $e'));
  }

  static Future<void> buy(String productId) async {
    final available = await InAppPurchase.instance.isAvailable();
    if (!available) {
      throw Exception('Google Play Billing not available on this device.');
    }
    final response = await InAppPurchase.instance.queryProductDetails({productId});
    if (response.productDetails.isEmpty) {
      throw Exception('Subscription "$productId" not found - it must be created in Google Play Console first.');
    }
    final purchaseParam = PurchaseParam(productDetails: response.productDetails.first);
    await InAppPurchase.instance.buyNonConsumable(purchaseParam: purchaseParam);
  }
}

// Cofre à parte para o "Secure Vault Files": um código de entrada PRÓPRIO,
// diferente do código que abre a app - quem sabe o código da app não vê
// automaticamente as fotos/documentos. Mesma técnica (Argon2id) que o
// PadlockVaultKey, só muda onde o sal fica guardado.
class VaultFilesKey {
  static const String _saltPrefsKey = 'padlock_vault_files_salt';
  static DateTime? _unlockedUntil;

  static bool get isUnlocked =>
      _unlockedUntil != null && DateTime.now().isBefore(_unlockedUntil!);

  static void markUnlocked() {
    _unlockedUntil = DateTime.now().add(const Duration(minutes: 5));
  }

  static void lock() {
    _unlockedUntil = null;
  }

  static Future<bool> hasVault() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_saltPrefsKey) != null;
  }

  static Future<Uint8List> createSalt() async {
    final random = Random.secure();
    final salt = Uint8List.fromList(List<int>.generate(16, (_) => random.nextInt(256)));
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_saltPrefsKey, base64Encode(salt));
    return salt;
  }

  static Future<Uint8List?> getSalt() async {
    final prefs = await SharedPreferences.getInstance();
    final saltBase64 = prefs.getString(_saltPrefsKey);
    if (saltBase64 == null) return null;
    return base64Decode(saltBase64);
  }

  static Future<void> wipe() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_saltPrefsKey);
  }
}

// Cofre da carteira cripto - código de entrada próprio (terceiro código,
// além do da app e do Vault Files), mesma técnica Argon2id.
class CryptoWalletKey {
  static const String _saltPrefsKey = 'padlock_crypto_wallet_salt';
  static DateTime? _unlockedUntil;

  static bool get isUnlocked =>
      _unlockedUntil != null && DateTime.now().isBefore(_unlockedUntil!);

  static void markUnlocked() {
    _unlockedUntil = DateTime.now().add(const Duration(minutes: 5));
  }

  static void lock() {
    _unlockedUntil = null;
  }

  static Future<bool> hasVault() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_saltPrefsKey) != null;
  }

  static Future<Uint8List> createSalt() async {
    final random = Random.secure();
    final salt = Uint8List.fromList(List<int>.generate(16, (_) => random.nextInt(256)));
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_saltPrefsKey, base64Encode(salt));
    return salt;
  }

  static Future<Uint8List?> getSalt() async {
    final prefs = await SharedPreferences.getInstance();
    final saltBase64 = prefs.getString(_saltPrefsKey);
    if (saltBase64 == null) return null;
    return base64Decode(saltBase64);
  }

  static Future<void> wipe() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_saltPrefsKey);
  }
}

// Uma moeda/token suportado pela carteira. contractAddress == null significa
// a moeda nativa da rede (POL); com endereço, é um token ERC-20 (ex: USDC).
// coingeckoId == null significa stablecoin - assumido a valer sempre ~1 USD,
// em vez de gastar mais um pedido de rede para confirmar o óbvio.
class CryptoToken {
  final String symbol;
  final String name;
  final int decimals;
  final EthereumAddress? contractAddress;
  final String? coingeckoId;
  const CryptoToken({required this.symbol, required this.name, required this.decimals, this.contractAddress, this.coingeckoId});
  bool get isNative => contractAddress == null;
}

// FASE 1 do Secure Crypto Vault: carteira não-custodial (a frase-semente
// nunca sai do telemóvel, nunca é enviada a nenhum servidor). Rede: Polygon
// Amoy (TESTNET) por agora - de propósito, para se poder testar tudo com
// tokens de teste sem qualquer valor real antes de alguma vez ligar a uma
// rede com dinheiro a sério.
class PadlockWallet {
  static const String rpcUrl = 'https://rpc-amoy.polygon.technology';
  // RPC pública de reserva - a principal (metida por defeito na Polygon Amoy)
  // por vezes está lenta ou temporariamente em baixo, o que fazia o saldo
  // falhar a carregar sem ser por culpa nenhuma da app.
  static const String rpcUrlFallback = 'https://polygon-amoy-bor-rpc.publicnode.com';
  static const int chainId = 80002; // Polygon Amoy (rede de teste)
  static const String derivationPath = "m/44'/60'/0'/0/0";

  // Endereço oficial do contrato USDC de testnet na Polygon Amoy, confirmado
  // na documentação da Circle (developers.circle.com/stablecoins/usdc-contract-addresses).
  // NÃO inventar/adivinhar endereços de tokens - um contrato errado pode
  // parecer funcionar e na verdade não mover fundo nenhum, ou pior.
  static final EthereumAddress usdcAddress = EthereumAddress.fromHex('0x41E94Eb019C0762f9Bfcf9Fb1E58725BfB0e7582');

  // Lista de moedas que a carteira sabe mostrar/enviar. Adicionar mais no
  // futuro é só acrescentar aqui, desde que o endereço do contrato seja
  // confirmado numa fonte oficial primeiro.
  static List<CryptoToken> get supportedTokens => [
        const CryptoToken(symbol: 'POL', name: 'Polygon (native)', decimals: 18, coingeckoId: 'polygon-ecosystem-token'),
        CryptoToken(symbol: 'USDC', name: 'USD Coin (testnet)', decimals: 6, contractAddress: usdcAddress),
      ];

  static const String _erc20AbiJson = '''
[
  {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"name":"account","type":"address"}],"outputs":[{"name":"","type":"uint256"}]},
  {"type":"function","name":"transfer","stateMutability":"nonpayable","inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"","type":"bool"}]}
]
''';

  static DeployedContract _erc20Contract(EthereumAddress address) {
    return DeployedContract(ContractAbi.fromJson(_erc20AbiJson, 'ERC20'), address);
  }

  // Converte a quantidade "humana" (ex: "12.5") para a unidade mais pequena
  // do token (ex: wei), a partir do TEXTO - nunca por multiplicação em vírgula
  // flutuante, que podia arredondar o valor de uma transação real.
  static BigInt parseUnits(String amount, int decimals) {
    final parts = amount.split('.');
    final wholePart = parts[0].isEmpty ? '0' : parts[0];
    String fracPart = parts.length > 1 ? parts[1] : '';
    if (fracPart.length > decimals) fracPart = fracPart.substring(0, decimals);
    fracPart = fracPart.padRight(decimals, '0');
    return BigInt.parse(wholePart + (fracPart.isEmpty ? '' : fracPart));
  }

  static String formatUnits(BigInt raw, int decimals) {
    final divisor = BigInt.from(10).pow(decimals);
    final whole = raw ~/ divisor;
    final fraction = (raw % divisor).toString().padLeft(decimals, '0');
    final trimmed = fraction.replaceFirst(RegExp(r'0+$'), '');
    return trimmed.isEmpty ? whole.toString() : '$whole.$trimmed';
  }

  static Future<BigInt> getTokenBalanceRaw(EthereumAddress owner, CryptoToken token) async {
    if (token.isNative) {
      final amount = await getBalance(owner);
      return amount.getInWei;
    }
    try {
      return await _withClient(rpcUrl, (client) => _readBalance(client, owner, token.contractAddress!));
    } catch (e) {
      print('Erro ao ler saldo do token na RPC principal, a tentar reserva: $e');
      return await _withClient(rpcUrlFallback, (client) => _readBalance(client, owner, token.contractAddress!));
    }
  }

  static Future<BigInt> _readBalance(Web3Client client, EthereumAddress owner, EthereumAddress tokenAddress) async {
    final contract = _erc20Contract(tokenAddress);
    final result = await client.call(contract: contract, function: contract.function('balanceOf'), params: [owner]);
    return result.first as BigInt;
  }

  // Cotação em USD via CoinGecko (API pública, sem chave). Stablecoins não
  // chamam a rede - valem sempre ~1 USD por definição. Devolve null se a
  // rede falhar, para o ecrã mostrar "sem cotação" em vez de um valor errado.
  static Future<double?> fetchUsdPrice(CryptoToken token) async {
    if (token.coingeckoId == null) return 1.0;
    try {
      final response = await http
          .get(Uri.parse('https://api.coingecko.com/api/v3/simple/price?ids=${token.coingeckoId}&vs_currencies=usd'))
          .timeout(const Duration(seconds: 8));
      if (response.statusCode != 200) return null;
      final decoded = jsonDecode(response.body) as Map<String, dynamic>;
      final entry = decoded[token.coingeckoId] as Map<String, dynamic>?;
      final price = entry?['usd'];
      return price is num ? price.toDouble() : null;
    } catch (e) {
      print('Erro ao obter cotação USD de ${token.symbol}: $e');
      return null;
    }
  }

  static bip39.Mnemonic generateMnemonic() {
    return bip39.Mnemonic.generate(bip39.Language.english);
  }

  static EthPrivateKey credentialsFromMnemonic(bip39.Mnemonic mnemonic) {
    final root = bip32.BIP32.fromSeed(Uint8List.fromList(mnemonic.seed));
    final child = root.derivePath(derivationPath);
    return EthPrivateKey(Uint8List.fromList(child.privateKey!));
  }

  static Future<void> storeMnemonic(Box walletBox, String sentence) async {
    await walletBox.put('mnemonic', sentence);
  }

  static String? readMnemonic(Box walletBox) {
    return walletBox.get('mnemonic');
  }

  static Future<EtherAmount> getBalance(EthereumAddress address) async {
    try {
      return await _withClient(rpcUrl, (client) => client.getBalance(address));
    } catch (e) {
      print('Erro ao ler saldo na RPC principal, a tentar reserva: $e');
      return await _withClient(rpcUrlFallback, (client) => client.getBalance(address));
    }
  }

  // Assina e transmite a transferência com a própria carteira do telemóvel -
  // a frase-semente nunca sai daqui, só a transação já assinada é que segue
  // para a rede. Testnet apenas por agora (ver aviso no ecrã).
  static Future<String> sendTransaction({
    required EthPrivateKey credentials,
    required EthereumAddress to,
    required EtherAmount amount,
  }) async {
    try {
      return await _withClient(rpcUrl, (client) => client.sendTransaction(
            credentials,
            Transaction(to: to, value: amount),
            chainId: chainId,
          ));
    } catch (e) {
      print('Erro ao enviar transação na RPC principal, a tentar reserva: $e');
      return await _withClient(rpcUrlFallback, (client) => client.sendTransaction(
            credentials,
            Transaction(to: to, value: amount),
            chainId: chainId,
          ));
    }
  }

  // Envio de token ERC-20 (ex: USDC) - a transação vai PARA o contrato do
  // token (não para o destinatário), com os dados codificados a dizer
  // "transfere X para Y". A frase-semente continua a nunca sair do telemóvel.
  static Future<String> sendErc20({
    required EthPrivateKey credentials,
    required EthereumAddress to,
    required EthereumAddress token,
    required BigInt rawAmount,
  }) async {
    final data = _erc20Contract(token).function('transfer').encodeCall([to, rawAmount]);
    try {
      return await _withClient(rpcUrl, (client) => client.sendTransaction(
            credentials,
            Transaction(to: token, data: data),
            chainId: chainId,
          ));
    } catch (e) {
      print('Erro ao enviar token na RPC principal, a tentar reserva: $e');
      return await _withClient(rpcUrlFallback, (client) => client.sendTransaction(
            credentials,
            Transaction(to: token, data: data),
            chainId: chainId,
          ));
    }
  }

  static Future<T> _withClient<T>(String url, Future<T> Function(Web3Client client) action) async {
    final client = Web3Client(url, http.Client());
    try {
      return await action(client).timeout(const Duration(seconds: 15));
    } finally {
      client.dispose();
    }
  }
}

// Guarda/lê as fotos e documentos do Secure Vault Files. Enquanto o cofre
// próprio dos ficheiros não estiver destrancado (ou nunca tiver sido criado),
// qualquer ficheiro que chegue fica em espera, já dentro do cofre principal
// (que está sempre aberto durante a sessão) - nunca fica nada por cifrar em
// lado nenhum, só muda QUAL chave o protege até seres tu a abrir o cofre de
// ficheiros e ele ser migrado para lá.
class VaultFilesStore {
  static String _newId() =>
      '${DateTime.now().millisecondsSinceEpoch}_${Random.secure().nextInt(1 << 32)}';

  static Future<void> _queuePending(Map<String, dynamic> entry) async {
    final vault = Hive.box('padlock_vault');
    final List pending = jsonDecode(vault.get('pending_vault_files') ?? '[]');
    pending.add(entry);
    await vault.put('pending_vault_files', jsonEncode(pending));
  }

  static Future<void> storeIncoming({
    required String peerId,
    required String fileName,
    required String fileKind,
    required String dataBase64,
    required int timestamp,
  }) async {
    await _queuePending({
      'id': _newId(),
      'peerId': peerId,
      'direction': 'received',
      'fileName': fileName,
      'fileKind': fileKind,
      'dataBase64': dataBase64,
      'timestamp': timestamp,
    });
  }

  static Future<void> storeSent({
    required String peerId,
    required String fileName,
    required String fileKind,
    required Uint8List fileBytes,
    String direction = 'sent',
  }) async {
    final entry = {
      'id': _newId(),
      'peerId': peerId,
      'direction': direction,
      'fileName': fileName,
      'fileKind': fileKind,
      'dataBase64': base64Encode(fileBytes),
      'timestamp': DateTime.now().millisecondsSinceEpoch,
    };
    if (VaultFilesKey.isUnlocked && Hive.isBoxOpen('padlock_vault_files')) {
      await _writeEntry(Hive.box('padlock_vault_files'), entry);
    } else {
      await _queuePending(entry);
    }
  }

  static Future<void> _writeEntry(Box filesBox, Map<String, dynamic> entry) async {
    final List index = jsonDecode(filesBox.get('index') ?? '[]');
    index.add({
      'id': entry['id'],
      'peerId': entry['peerId'],
      'direction': entry['direction'],
      'fileName': entry['fileName'],
      'fileKind': entry['fileKind'],
      'timestamp': entry['timestamp'],
    });
    await filesBox.put('index', jsonEncode(index));
    await filesBox.put('data_${entry['id']}', entry['dataBase64']);
  }

  static Future<void> migratePending(Box filesBox) async {
    final vault = Hive.box('padlock_vault');
    final String? pendingStr = vault.get('pending_vault_files');
    if (pendingStr == null) return;
    final List pending = jsonDecode(pendingStr);
    for (var item in pending) {
      await _writeEntry(filesBox, Map<String, dynamic>.from(item));
    }
    await vault.delete('pending_vault_files');
  }

  static List<Map<String, dynamic>> listEntries(Box filesBox) {
    final List index = jsonDecode(filesBox.get('index') ?? '[]');
    return index.map((e) => Map<String, dynamic>.from(e)).toList()
      ..sort((a, b) => (b['timestamp'] as int).compareTo(a['timestamp'] as int));
  }

  static Uint8List? readData(Box filesBox, String id) {
    final String? b64 = filesBox.get('data_$id');
    if (b64 == null) return null;
    return base64Decode(b64);
  }

  static Future<void> deleteEntry(Box filesBox, String id) async {
    final List index = jsonDecode(filesBox.get('index') ?? '[]');
    index.removeWhere((e) => e['id'] == id);
    await filesBox.put('index', jsonEncode(index));
    await filesBox.delete('data_$id');
  }
}

// Double Ratchet (cadeia simétrica + ratchet Diffie-Hellman), ao estilo Signal:
// além da cadeia de hash que avança a cada mensagem (sigilo perante o futuro -
// uma chave antiga nunca destranca mensagens novas), sempre que a conversa
// "muda de sentido" (a outra parte responde) as duas partes fazem um novo
// Diffie-Hellman e criam uma cadeia totalmente nova a partir daí. Isto dá
// "post-compromise security": mesmo que um atacante roube uma chave da
// cadeia num certo momento, assim que houver uma resposta a conversa
// "cura-se" sozinha e volta a ficar ilegível para quem só tinha essa chave.
class PadlockRatchet {
  static const List<int> _msgKeyConstant = [0x01];
  static const List<int> _chainKeyConstant = [0x02];

  static Future<void> establishChains({
    required String peerId,
    required String myId,
    required List<int> sharedSecretBytes,
    required List<int> myHandshakePrivateKeyBytes,
    required List<int> myHandshakePublicKeyBytes,
    required List<int> theirHandshakePublicKeyBytes,
  }) async {
    final hmac = crypto.Hmac.sha256();
    final mac1 = await hmac.calculateMac(
      utf8.encode('padlock-chain-1'),
      secretKey: crypto.SecretKey(sharedSecretBytes),
    );
    final mac2 = await hmac.calculateMac(
      utf8.encode('padlock-chain-2'),
      secretKey: crypto.SecretKey(sharedSecretBytes),
    );
    final rootMac = await hmac.calculateMac(
      utf8.encode('padlock-root'),
      secretKey: crypto.SecretKey(sharedSecretBytes),
    );

    final vault = Hive.box('padlock_vault');
    final amFirst = myId.compareTo(peerId) < 0;

    // Cadeias simétricas de arranque, iguais para os dois lados (tal como
    // sempre foi): garantem que QUALQUER um dos dois pode escrever a
    // primeira mensagem sem ter de esperar por uma resposta - um Double
    // Ratchet "de manual" obriga o lado que não iniciou a esperar pela
    // primeira mensagem do outro antes de poder responder, o que não faz
    // sentido numa app de chat onde qualquer um pode escrever primeiro.
    await vault.put('chain_send_$peerId', base64Encode(amFirst ? mac1.bytes : mac2.bytes));
    await vault.put('chain_recv_$peerId', base64Encode(amFirst ? mac2.bytes : mac1.bytes));
    await vault.put('chain_send_n_$peerId', 0);
    await vault.put('chain_recv_n_$peerId', 0);
    await vault.delete('skipped_keys_$peerId');
    await vault.delete('shared_secret_$peerId');

    // Estado base do ratchet DH: o par de chaves do handshake serve de
    // "chave de ratchet" inicial de cada lado (ambos já a conhecem, tal
    // como o "prekey" do Signal).
    await vault.put('dr_root_$peerId', base64Encode(rootMac.bytes));
    await vault.put('dr_dhs_priv_$peerId', base64Encode(myHandshakePrivateKeyBytes));
    await vault.put('dr_dhs_pub_$peerId', base64Encode(myHandshakePublicKeyBytes));
    await vault.put('dr_dhr_pub_$peerId', base64Encode(theirHandshakePublicKeyBytes));

    if (amFirst) {
      // Papel equivalente ao "Alice" do protocolo Signal: em vez de reutilizar
      // a chave do handshake para enviar, gera já uma chave de ratchet nova e
      // faz logo o 1º passo do ratchet DH - a primeira mensagem já nasce
      // "curada" à frente, sem esperar por uma resposta.
      await _selfRatchetAsInitiator(peerId, theirHandshakePublicKeyBytes);
    }
  }

  static Future<void> _selfRatchetAsInitiator(String peerId, List<int> theirDhPubBytes) async {
    final vault = Hive.box('padlock_vault');
    final algorithm = crypto.X25519();

    final rootKey = base64Decode(vault.get('dr_root_$peerId'));

    final freshKeyPair = await algorithm.newKeyPair();
    final freshPriv = await freshKeyPair.extractPrivateKeyBytes();
    final freshPub = (await freshKeyPair.extractPublicKey()).bytes;

    final theirPublicKey = crypto.SimplePublicKey(theirDhPubBytes, type: crypto.KeyPairType.x25519);
    final dhOutput = await algorithm.sharedSecretKey(keyPair: freshKeyPair, remotePublicKey: theirPublicKey);
    final dhOutputBytes = await dhOutput.extractBytes();

    final kdf = await _kdfRk(rootKey, dhOutputBytes);

    await vault.put('dr_root_$peerId', base64Encode(kdf['root']!));
    await vault.put('dr_dhs_priv_$peerId', base64Encode(freshPriv));
    await vault.put('dr_dhs_pub_$peerId', base64Encode(freshPub));
    await vault.put('chain_send_$peerId', base64Encode(kdf['chain']!));
    await vault.put('chain_send_n_$peerId', 0);
  }

  // Passo do ratchet DH, disparado quando se recebe uma mensagem com uma
  // chave de ratchet do outro lado diferente da que tínhamos guardada -
  // sinal de que houve uma "resposta" e é altura de renovar as duas cadeias.
  static Future<void> _performDhRatchet(String peerId, String theirNewDhPubB64) async {
    final vault = Hive.box('padlock_vault');
    final algorithm = crypto.X25519();

    final rootB64 = vault.get('dr_root_$peerId');
    final myDhsPrivB64 = vault.get('dr_dhs_priv_$peerId');
    if (rootB64 == null || myDhsPrivB64 == null) return; // handshake incompleto: nada a fazer

    var rootKey = base64Decode(rootB64);
    final theirNewPubBytes = base64Decode(theirNewDhPubB64);
    final theirNewPublicKey = crypto.SimplePublicKey(theirNewPubBytes, type: crypto.KeyPairType.x25519);

    // 1. DH com a MINHA chave de ratchet atual + a chave nova deles -> nova cadeia de receção
    final myCurrentKeyPair = await algorithm.newKeyPairFromSeed(base64Decode(myDhsPrivB64));
    final dhOut1 = await algorithm.sharedSecretKey(keyPair: myCurrentKeyPair, remotePublicKey: theirNewPublicKey);
    final kdf1 = await _kdfRk(rootKey, await dhOut1.extractBytes());
    rootKey = kdf1['root']!;

    // 2. Gero já uma chave de ratchet nova minha e faço DH outra vez -> nova cadeia de envio
    // (assim a MINHA próxima mensagem já vai com uma chave fresca, tal como faria o Signal)
    final myNewKeyPair = await algorithm.newKeyPair();
    final myNewPrivBytes = await myNewKeyPair.extractPrivateKeyBytes();
    final myNewPubBytes = (await myNewKeyPair.extractPublicKey()).bytes;
    final dhOut2 = await algorithm.sharedSecretKey(keyPair: myNewKeyPair, remotePublicKey: theirNewPublicKey);
    final kdf2 = await _kdfRk(rootKey, await dhOut2.extractBytes());

    await vault.put('dr_root_$peerId', base64Encode(kdf2['root']!));
    await vault.put('dr_dhr_pub_$peerId', theirNewDhPubB64);
    await vault.put('chain_recv_$peerId', base64Encode(kdf1['chain']!));
    await vault.put('chain_recv_n_$peerId', 0);
    await vault.delete('skipped_keys_$peerId'); // cadeia nova: os índices recomeçam do zero

    await vault.put('dr_dhs_priv_$peerId', base64Encode(myNewPrivBytes));
    await vault.put('dr_dhs_pub_$peerId', base64Encode(myNewPubBytes));
    await vault.put('chain_send_$peerId', base64Encode(kdf2['chain']!));
    await vault.put('chain_send_n_$peerId', 0);
  }

  static Future<Map<String, Uint8List>> _kdfRk(List<int> rootKey, List<int> dhOutput) async {
    final hmac = crypto.Hmac.sha256();
    final rootMac = await hmac.calculateMac([...dhOutput, 0x01], secretKey: crypto.SecretKey(rootKey));
    final chainMac = await hmac.calculateMac([...dhOutput, 0x02], secretKey: crypto.SecretKey(rootKey));
    return {
      'root': Uint8List.fromList(rootMac.bytes),
      'chain': Uint8List.fromList(chainMac.bytes),
    };
  }

  static Future<Uint8List> _step(List<int> chainKey, List<int> constant) async {
    final hmac = crypto.Hmac.sha256();
    final mac = await hmac.calculateMac(constant, secretKey: crypto.SecretKey(chainKey));
    return Uint8List.fromList(mac.bytes);
  }

  static Future<Map<String, dynamic>> nextSendKey(String peerId) async {
    final vault = Hive.box('padlock_vault');
    final chainBase64 = vault.get('chain_send_$peerId');
    if (chainBase64 == null) {
      throw Exception('Sem cadeia de envio para $peerId. Handshake incompleto.');
    }
    final chain = base64Decode(chainBase64);
    final msgKey = await _step(chain, _msgKeyConstant);
    final nextChain = await _step(chain, _chainKeyConstant);
    final n = (vault.get('chain_send_n_$peerId') ?? 0) as int;

    await vault.put('chain_send_$peerId', base64Encode(nextChain));
    await vault.put('chain_send_n_$peerId', n + 1);

    final dhsPub = vault.get('dr_dhs_pub_$peerId') as String?;
    return {'key': msgKey, 'index': n, 'dh': dhsPub};
  }

  // theirDhPub: chave de ratchet atual de quem enviou (vem no cabeçalho da
  // mensagem). Se for diferente da que tínhamos guardada, dispara um passo
  // do ratchet DH antes de sequer tentar decifrar.
  static Future<Uint8List?> receiveMessageKey(String peerId, int targetIndex, {String? theirDhPub}) async {
    final vault = Hive.box('padlock_vault');

    if (theirDhPub != null && theirDhPub.isNotEmpty) {
      final storedDhr = vault.get('dr_dhr_pub_$peerId') as String?;
      if (storedDhr != null && storedDhr != theirDhPub) {
        await _performDhRatchet(peerId, theirDhPub);
      } else if (storedDhr == null) {
        await vault.put('dr_dhr_pub_$peerId', theirDhPub);
      }
    }

    final skippedStr = vault.get('skipped_keys_$peerId');
    Map<String, dynamic> skipped = skippedStr != null ? jsonDecode(skippedStr) : {};
    if (skipped.containsKey(targetIndex.toString())) {
      final keyB64 = skipped.remove(targetIndex.toString());
      await vault.put('skipped_keys_$peerId', jsonEncode(skipped));
      return base64Decode(keyB64);
    }

    final chainBase64 = vault.get('chain_recv_$peerId');
    if (chainBase64 == null) return null;

    var chain = base64Decode(chainBase64);
    var n = (vault.get('chain_recv_n_$peerId') ?? 0) as int;

    if (targetIndex < n) return null;
    if (targetIndex - n > 100) return null;

    Uint8List? finalKey;
    while (n <= targetIndex) {
      final msgKey = await _step(chain, _msgKeyConstant);
      chain = await _step(chain, _chainKeyConstant);
      if (n == targetIndex) {
        finalKey = msgKey;
      } else {
        skipped[n.toString()] = base64Encode(msgKey);
      }
      n++;
    }

    await vault.put('chain_recv_$peerId', base64Encode(chain));
    await vault.put('chain_recv_n_$peerId', n);
    await vault.put('skipped_keys_$peerId', jsonEncode(skipped));
    return finalKey;
  }

  // Destruição forense completa do canal com um contacto: apaga TODO o
  // estado do Double Ratchet (cadeias, chaves de ratchet, raiz) e a chave
  // pública trancada pelo TOFU. Sem isto, apagar/bloquear um contacto só
  // parecia destruir as chaves - o estado do ratchet e o pin do TOFU
  // continuavam no disco, extraíveis numa análise forense.
  static Future<void> purgeContactKeys(String peerId) async {
    final vault = Hive.box('padlock_vault');
    await vault.delete('shared_secret_$peerId');
    await vault.delete('private_key_$peerId');
    await vault.delete('chain_send_$peerId');
    await vault.delete('chain_recv_$peerId');
    await vault.delete('chain_send_n_$peerId');
    await vault.delete('chain_recv_n_$peerId');
    await vault.delete('chain_send_pn_$peerId');
    await vault.delete('skipped_keys_$peerId');
    await vault.delete('dr_root_$peerId');
    await vault.delete('dr_dhs_priv_$peerId');
    await vault.delete('dr_dhs_pub_$peerId');
    await vault.delete('dr_dhr_pub_$peerId');
    await vault.delete('chave_publica_trancada_$peerId');
    await vault.delete('my_public_key_$peerId');
    await vault.delete('their_public_key_$peerId');
  }
}
final GlobalKey<NavigatorState> navigatorKey = GlobalKey<NavigatorState>();

const int kMaxVaultFileBytes = 6 * 1024 * 1024; // 6MB - limite do relay atual (um único frame WebSocket)

// Cifra e envia uma foto/documento pelo mesmo canal Double Ratchet das
// mensagens de texto (mesma chave por mensagem, mesmo AES-256-GCM) - nome e
// tipo do ficheiro vão também cifrados lá dentro, nunca em texto simples no
// pacote que o servidor vê.
Future<void> sendEncryptedFile({
  required String targetId,
  required Uint8List fileBytes,
  required String fileName,
  required String fileKind, // 'photo' ou 'document'
}) async {
  if (fileBytes.length > kMaxVaultFileBytes) {
    throw Exception('File too large (max ${kMaxVaultFileBytes ~/ (1024 * 1024)}MB).');
  }
  final innerPayload = jsonEncode({'name': fileName, 'kind': fileKind, 'data': base64Encode(fileBytes)});

  final result = await PadlockRatchet.nextSendKey(targetId);
  final key = enc.Key(Uint8List.fromList(result['key'] as List<int>));
  final iv = enc.IV.fromSecureRandom(16);
  final encrypter = enc.Encrypter(enc.AES(key, mode: enc.AESMode.gcm));
  final encrypted = encrypter.encrypt(innerPayload, iv: iv);
  final payload = '${iv.base64}:${encrypted.base64}';

  final myId = Hive.box('padlock_vault').get('user_privacy_id');
  PadlockNetwork.channel?.sink.add(jsonEncode({
    'type': 'secure_file',
    'senderId': myId,
    'targetId': targetId,
    'payload': payload,
    'chainIndex': result['index'],
    'dh': result['dh'] ?? '',
    'timestamp': DateTime.now().millisecondsSinceEpoch,
  }));

  await VaultFilesStore.storeSent(
    peerId: targetId,
    fileName: fileName,
    fileKind: fileKind,
    fileBytes: fileBytes,
  );
}

// Mensagem de voz: mesmo túnel cifrado (Double Ratchet + AES-256-GCM) que o
// texto e os ficheiros, mas fica dentro da própria conversa (não vai para o
// Secure Vault Files) - toca-se logo ali, como uma mensagem normal.
Future<void> sendEncryptedVoice({
  required String targetId,
  required Uint8List audioBytes,
}) async {
  if (audioBytes.length > kMaxVaultFileBytes) {
    throw Exception('Voice message too long (max ${kMaxVaultFileBytes ~/ (1024 * 1024)}MB).');
  }
  final innerPayload = jsonEncode({'data': base64Encode(audioBytes)});

  final result = await PadlockRatchet.nextSendKey(targetId);
  final key = enc.Key(Uint8List.fromList(result['key'] as List<int>));
  final iv = enc.IV.fromSecureRandom(16);
  final encrypter = enc.Encrypter(enc.AES(key, mode: enc.AESMode.gcm));
  final encrypted = encrypter.encrypt(innerPayload, iv: iv);
  final payload = '${iv.base64}:${encrypted.base64}';

  final myId = Hive.box('padlock_vault').get('user_privacy_id');
  PadlockNetwork.channel?.sink.add(jsonEncode({
    'type': 'secure_voice',
    'senderId': myId,
    'targetId': targetId,
    'payload': payload,
    'chainIndex': result['index'],
    'dh': result['dh'] ?? '',
    'timestamp': DateTime.now().millisecondsSinceEpoch,
  }));
}

Future<String> decryptSecureMessage(String peerId, Map<String, dynamic> data) async {
  final payloadParts = data['payload'].toString().split(':');
  final chainIndex = data['chainIndex'] as int? ?? 0;
  final theirDhPub = data['dh'] as String?;

  if (payloadParts.length != 2) return '[Message not decrypted]';

  try {
    final msgKeyBytes = await PadlockRatchet.receiveMessageKey(peerId, chainIndex, theirDhPub: theirDhPub);
    if (msgKeyBytes == null) return '[Message not decrypted]';

    final key = enc.Key(Uint8List.fromList(msgKeyBytes));
    final iv = enc.IV.fromBase64(payloadParts[0]);
    final encryptedData = enc.Encrypted.fromBase64(payloadParts[1]);
    final encrypter = enc.Encrypter(enc.AES(key, mode: enc.AESMode.gcm));
    return encrypter.decrypt(encryptedData, iv: iv);
  } catch (e) {
    print('Erro ao decifrar: $e');
    return '[Message not decrypted]';
  }
}
final FlutterLocalNotificationsPlugin flutterLocalNotificationsPlugin = FlutterLocalNotificationsPlugin();
@pragma('vm:entry-point')
Future<void> _firebaseMessagingBackgroundHandler(RemoteMessage message) async {
  await Firebase.initializeApp();

  final FlutterLocalNotificationsPlugin localNotif = FlutterLocalNotificationsPlugin();
  const AndroidInitializationSettings initSettingsAndroid = AndroidInitializationSettings('@mipmap/ic_launcher');
  await localNotif.initialize(const InitializationSettings(android: initSettingsAndroid));

  // Deteta o que o servidor mandou (se é chamada, fim de chamada, ou mensagem)
  final bool isCall = message.data['action'] == 'call_offer';
  final bool isCallEnd = message.data['action'] == 'call_end';
  final String senderId = message.data['senderId'] ?? 'Unknown';
  final int notificationId = senderId.hashCode;

  if (isCallEnd) {
    // Quem ligou desistiu/desligou antes de a chamada ser atendida - sem
    // isto, o ecrã nativo (CallKit) ficava a tocar até ao limite de 60s,
    // mesmo já não havendo chamada nenhuma do outro lado.
    await FlutterCallkitIncoming.endAllCalls();
    return;
  }

  if (isCall) {
    // DISPARA O ECRÃ NATIVO DE CHAMADA DO TELEMÓVEL
    await FlutterCallkitIncoming.showCallkitIncoming(
      CallKitParams(
        id: senderId,
        nameCaller: 'Padlock - $senderId',
        appName: 'Padlock',
        avatar: '',
        handle: 'Encrypted Call',
        type: 0,
        duration: 60000,
        textAccept: 'Atender',
        textDecline: 'Recusar',
        extra: {'targetId': senderId, 'sdp': message.data['sdp'], 'isVideo': message.data['isVideo']},
        android: const AndroidParams(
          isCustomNotification: true,
          isShowLogo: true,
          backgroundColor: '#000000',
          actionColor: '#00FF66',
          ringtonePath: 'ringtone',
        ),
      ),
    );
    // Avisa já quem ligou que o telemóvel está mesmo a tocar. Sem isto, com a
    // app morta, esse aviso só saía depois de a chamada ser aceite (tarde
    // demais) - o ecrã de quem ligava ficava preso em "Connecting..." com o
    // som de Morse a tocar durante todo o tempo em que o outro lado já
    // estava a tocar de verdade.
    try {
      final tempChannel = WebSocketChannel.connect(Uri.parse('wss://servidor-padlock.onrender.com'));
      tempChannel.sink.add(jsonEncode({'action': 'call_ringing', 'targetId': senderId}));
      Future.delayed(const Duration(milliseconds: 1500), () => tempChannel.sink.close());
    } catch (e) {
      print('Erro ao avisar que está a tocar: $e');
    }
  } else {
    // --- POP-UP DE MENSAGEM MILITAR ---
    const AndroidNotificationDetails msgDetails = AndroidNotificationDetails(
      'padlock_msg_channel', 'Secure Messages',
      importance: Importance.max,
      priority: Priority.high,
      playSound: true,
    );

    await localNotif.show(
      notificationId,
      'Padlock',
      'You have an encrypted message',
      const NotificationDetails(android: msgDetails),
      payload: 'msg:$senderId',
    );
  }
}
void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await Firebase.initializeApp();
  FlutterCallkitIncoming.onEvent.listen((event) {
   if (event!.event == Event.actionCallAccept) {
      if (PadlockNetwork.emChamada) return;
      PadlockNetwork.emChamada = true;
      final targetId = event.body['extra']['targetId'];
      final sdp = jsonDecode(event.body['extra']['sdp']);
      final isVideoCall = event.body['extra']['isVideo'] == 'true' || event.body['extra']['isVideo'] == true;

      PadlockNetwork.pendingCallData = {'targetId': targetId, 'sdp': sdp, 'isVideo': isVideoCall};

      if (!PadlockNetwork.isUnlocked) {
        // Cofre ainda fechado (app estava morta): fica em espera no LoginScreen.
        // A navegação para o ActiveCallScreen acontece em LoginScreen._login()
        // depois do PIN correto, usando PadlockNetwork.pendingCallData.
        return;
      }

      void abrirEcraChamada(int tentativas) {
        if (navigatorKey.currentState != null) {
          PadlockCallOverlay.show(ActiveCallScreen(
            local: t['EN']!,
            recipientName: targetId,
            targetId: targetId,
            isIncoming: true,
            channel: PadlockNetwork.channel,
            incomingSdp: sdp,
            acceptedViaCallKit: true,
            isVideo: isVideoCall,
          ));
        } else if (tentativas > 0) {
          Future.delayed(const Duration(milliseconds: 200), () => abrirEcraChamada(tentativas - 1));
        }
      }
      abrirEcraChamada(20);
    } else if (event.event == Event.actionCallDecline) {
      FlutterCallkitIncoming.endAllCalls();
        final targetId = event.body['extra']['targetId'];
        final tempChannel = WebSocketChannel.connect(Uri.parse('wss://servidor-padlock.onrender.com'));
        tempChannel.sink.add(jsonEncode({'action': 'call_end', 'targetId': targetId}));
        Future.delayed(const Duration(milliseconds: 1500), () => tempChannel.sink.close());
        // Recusar explicitamente também tem de ficar registado na conversa -
        // antes, só o esgotar do tempo (60s sem resposta) ficava gravado, e
        // recusar de propósito não deixava rasto nenhum no chat.
        if (Hive.isBoxOpen('padlock_vault')) {
          final vault = Hive.box('padlock_vault');
          List allChats = jsonDecode(vault.get('chats') ?? '[]');
          int idx = allChats.indexWhere((c) => c['id'] == targetId);
          if (idx != -1) {
            final timeStr = "${DateTime.now().hour.toString().padLeft(2, '0')}:${DateTime.now().minute.toString().padLeft(2, '0')}";
            allChats[idx]['messages'].add({'text': '📞 Missed Secure Call ($timeStr)', 'isMe': false, 'status': 'missed', 'timestamp': DateTime.now().millisecondsSinceEpoch});
            allChats[idx]['msg'] = '📞 Missed Secure Call';
            allChats[idx]['unread'] = (allChats[idx]['unread'] ?? 0) + 1;
            vault.put('chats', jsonEncode(allChats));
          }
        }

      } else if (event!.event == Event.actionCallTimeout) {
        final targetId = event.body['extra']['targetId'];
        if (!Hive.isBoxOpen('padlock_vault')) return; // cofre ainda fechado (sem PIN): não há onde gravar
        final vault = Hive.box('padlock_vault');
        List allChats = jsonDecode(vault.get('chats') ?? '[]');
        int idx = allChats.indexWhere((c) => c['id'] == targetId);
        if (idx != -1) {
          final timeStr = "${DateTime.now().hour.toString().padLeft(2, '0')}:${DateTime.now().minute.toString().padLeft(2, '0')}";
          allChats[idx]['messages'].add({'text': '📞 Missed Call ($timeStr)', 'isMe': false, 'status': 'missed', 'timestamp': DateTime.now().millisecondsSinceEpoch});
          allChats[idx]['msg'] = '📞 Missed Call';
          allChats[idx]['unread'] = (allChats[idx]['unread'] ?? 0) + 1;
          vault.put('chats', jsonEncode(allChats));
        }
        }
  });
  
  FirebaseMessaging.onBackgroundMessage(_firebaseMessagingBackgroundHandler);
  final fcmToken = await FirebaseMessaging.instance.getToken();
  
  const AndroidInitializationSettings initializationSettingsAndroid = AndroidInitializationSettings('@mipmap/ic_launcher');
  const InitializationSettings initializationSettings = InitializationSettings(android: initializationSettingsAndroid);
  await flutterLocalNotificationsPlugin.initialize(initializationSettings);
  final AndroidFlutterLocalNotificationsPlugin? androidImplementation = flutterLocalNotificationsPlugin.resolvePlatformSpecificImplementation<AndroidFlutterLocalNotificationsPlugin>();
androidImplementation?.requestNotificationsPermission();
  // 1. Inicializa o motor da Base de Dados Blindada (Hive)
  await Hive.initFlutter();

  // 2. O cofre NÃO abre aqui. A chave de encriptação (Argon2id) só existe depois
  // do utilizador escrever a sua frase de encriptação no SetupScreen/LoginScreen -
  // nunca fica guardada em disco. Enquanto isso, guarda o token FCM em memória
  // para o escrever no cofre assim que ele abrir.
  PadlockNetwork.pendingFcmToken = fcmToken;

  // 3. Arranca a rede (ainda sem identidade - só liga o túnel WebSocket)
  PadlockNetwork.initNetworkListener();

  // Bug encontrado: quando a app está ABERTA mas ainda BLOQUEADA (parada no
  // LoginScreen, sem ter entrado ainda), o servidor vê o telemóvel "online"
  // e entrega a chamada diretamente pelo túnel WebSocket em vez de empurrar
  // por FCM (só empurra por FCM quando o socket não está ligado). Como não
  // havia nenhum ouvinte para uma mensagem 'offer' crua chegar por este
  // caminho enquanto bloqueada, a chamada não tocava, não aparecia
  // notificação nem ecrã nenhum - ficava completamente muda.
  //
  // IMPORTANTE: isto só pode disparar quando a app está BLOQUEADA. Quando
  // já está desbloqueada (dentro da app normal), o próprio
  // _MainNavigationScreenState já trata esta mesma mensagem 'call_offer' e
  // abre o ActiveCallScreen diretamente, sem CallKit nenhum - por isso, sem
  // este "if (PadlockNetwork.isUnlocked) return", os dois ouviam a MESMA
  // mensagem (o messageHub é partilhado) e mostravam DOIS ecrãs de chamada
  // ao mesmo tempo (CallKit + ActiveCallScreen), cada um a tocar por si e
  // sem saber do outro - atender um deixava o outro a tocar para sempre.
  PadlockNetwork.messageHub.stream.listen((raw) {
    try {
      final data = jsonDecode(raw);
      if (data['type'] == 'offer' && data['action'] == 'call_offer') {
        if (PadlockNetwork.emChamada) return;
        if (PadlockNetwork.isUnlocked) return;
        final senderId = data['senderId'] ?? 'Unknown';
        FlutterCallkitIncoming.showCallkitIncoming(
          CallKitParams(
            id: senderId,
            nameCaller: 'Padlock - $senderId',
            appName: 'Padlock',
            avatar: '',
            handle: 'Encrypted Call',
            type: 0,
            duration: 60000,
            textAccept: 'Atender',
            textDecline: 'Recusar',
            extra: {
              'targetId': senderId,
              'sdp': jsonEncode(data['sdp']),
              'isVideo': data['isVideo'].toString(),
            },
            android: const AndroidParams(
              isCustomNotification: true,
              isShowLogo: true,
              backgroundColor: '#000000',
              actionColor: '#00FF66',
              ringtonePath: 'ringtone',
            ),
          ),
        );
      }
    } catch (_) {}
  });

  PremiumService.init();
  bool isFirstTime = !(await PadlockVaultKey.hasVault());
  FirebaseMessaging.instance.getInitialMessage().then((message) {
    if (message != null && message.data['action'] == 'call_offer') {
      if (PadlockNetwork.emChamada) return;
      final senderId = message.data['senderId'] ?? 'Unknown';
      final isVideoCall = message.data['isVideo'] == 'true';
      PadlockNetwork.pendingCallData = {'targetId': senderId, 'sdp': message.data['sdp'], 'isVideo': isVideoCall};
      if (!PadlockNetwork.isUnlocked) return;
      Future.delayed(const Duration(seconds: 1), () {
        PadlockCallOverlay.show(ActiveCallScreen(
          local: t['EN']!,
          recipientName: senderId,
          targetId: senderId,
          isIncoming: true,
          incomingSdp: message.data['sdp'],
          channel: PadlockNetwork.channel,
          isVideo: isVideoCall,
        ));
      });
    }
  });

  FirebaseMessaging.onMessageOpenedApp.listen((message) {
    if (message.data['action'] == 'call_offer') {
      if (PadlockNetwork.emChamada) return;
      final senderId = message.data['senderId'] ?? 'Unknown';
      final isVideoCall = message.data['isVideo'] == 'true';
      PadlockNetwork.pendingCallData = {'targetId': senderId, 'sdp': message.data['sdp'], 'isVideo': isVideoCall};
      if (!PadlockNetwork.isUnlocked) return;
      PadlockCallOverlay.show(ActiveCallScreen(
        local: t['EN']!,
        recipientName: senderId,
        targetId: senderId,
        isIncoming: true,
        channel: PadlockNetwork.channel,
        isVideo: isVideoCall,
      ));
    }
  });
  runApp(PadlockApp(isFirstTime: isFirstTime));
}

class PadlockApp extends StatefulWidget {
  final bool isFirstTime;
  
  const PadlockApp({super.key, required this.isFirstTime});

  @override
  State<PadlockApp> createState() => _PadlockAppState();
}

class _PadlockAppState extends State<PadlockApp> with WidgetsBindingObserver {
  String _currentLanguage = 'EN';

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  // Botão de voltar do Android, capturado ao nível da app inteira,
  // independentemente do ecrã em que se está. Enquanto a chamada estiver a
  // ecrã inteiro, minimiza-a em vez de fazer o que quer que o ecrã por
  // baixo fizesse - é isto que impede o botão de voltar de destruir a
  // chamada, seja qual for o ecrã aberto por baixo.
  @override
  Future<bool> didPopRoute() async {
    if (PadlockCallOverlay.isActive && !PadlockCallOverlay.minimized.value) {
      PadlockCallOverlay.minimized.value = true;
      return true;
    }
    return false;
  }

  void _changeLanguage(String lang) {
    setState(() {
      _currentLanguage = lang;
    });
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      navigatorKey: navigatorKey,
      debugShowCheckedModeBanner: false,
      title: 'PADLOCK',
      
      theme: ThemeData(
        brightness: Brightness.dark,
        scaffoldBackgroundColor: Colors.black,
        primaryColor: const Color(0xFF8B0000),
        bottomNavigationBarTheme: const BottomNavigationBarThemeData(
          backgroundColor: Color(0xFF0F0F0F),
          selectedItemColor: const Color(0xFF00FF66),
          unselectedItemColor: Colors.grey,
        ),
      ),
     home: widget.isFirstTime ? const SetupScreen() : const LoginScreen(),
    );
  }
}

// Base de dados de traduções do sistema
Map<String, Map<String, String>> t = {
  'EN': {
    'chats': 'Chats',
    'contacts': 'Contacts',
    'settings': 'Settings',
    'profile': 'Profile',
    'search_hint': 'Search secure database...',
    'autodestruct': 'Auto-destructs in',
    'bio_label': 'Bio',
    'bio_text': 'P2P Encrypted Node / Military-Grade Security',
    'username_label': 'Username',
    'copy_toast': 'ID copied to clipboard!',
    'qr_title': 'Privacy QR Code',
    'qr_desc': 'Scan this code to establish a peer-to-peer secure handshake.',
    'call': 'Secure Call',
    'new_chat': 'New Secure Channel',
    'delete_chat': 'Wipe Conversation',
    'block_peer': 'Block Hex ID',
    'send_hint': 'Type encrypted message...',
    'custom_sound': 'Padlock Secure Sound (Fixed)',
    'silent_mode': 'Silent Mode',
    'notifications': 'Notifications',
    'sounds_desc': 'System uses exclusive encrypted tones.',
    'app_lock': 'Passcode Lock',
    'screen_security': 'Block Screenshots',
    'clear_keys': 'Purge Encryption Keys',
    'keys_purged': 'All session keys have been shredded safely.',
    'offline_contacts': 'P2P Active Contacts',
    'empty_contacts': 'No peer contacts discovered in local mesh.',
  },
  'PT': {
    'chats': 'Conversas',
    'contacts': 'Contactos',
    'settings': 'Definições',
    'profile': 'Perfil',
    'search_hint': 'Procurar base de dados segura...',
    'autodestruct': 'Auto-destruição em',
    'bio_label': 'Biografia',
    'bio_text': 'Nó Encriptado P2P / Segurança de Nível Militar',
    'username_label': 'Nome de utilizador',
    'copy_toast': 'ID copiado para a área de transferência!',
    'qr_title': 'Código QR de Privacidade',
    'qr_desc': 'Digitaliza este código para estabelecer uma ligação direta P2P segura.',
    'call': 'Chamada Segura',
    'new_chat': 'Novo Canal Seguro',
    'delete_chat': 'Apagar Conversa',
    'block_peer': 'Bloquear ID Hex',
    'send_hint': 'Escreve mensagem encriptada...',
    'custom_sound': 'Toque Exclusivo Padlock (Fixo)',
    'silent_mode': 'Modo Silencioso',
    'notifications': 'Notificações',
    'sounds_desc': 'O sistema usa tons encriptados exclusivos.',
    'app_lock': 'Bloqueio por Código',
    'screen_security': 'Bloquear Capturas de Ecrã',
    'clear_keys': 'Purgar Chaves de Encriptação',
    'keys_purged': 'Todas as chaves de sessão foram destruídas de forma segura.',
    'offline_contacts': 'Contactos Ativos P2P',
    'empty_contacts': 'Nenhum contacto detetado na rede local.',
  },
  'ES': {
    'chats': 'Chats',
    'contacts': 'Contactos',
    'settings': 'Ajustes',
    'profile': 'Perfil',
    'search_hint': 'Buscar base de datos segura...',
    'autodestruct': 'Autodestrucción en',
    'bio_label': 'Biografía',
    'bio_text': 'Nodo encriptado P2P / Seguridad de nivel militar',
    'username_label': 'Nombre de usuario',
    'copy_toast': '¡ID copiado al portapapeles!',
    'qr_title': 'Código QR de privacidad',
    'qr_desc': 'Escanea este código para establecer una conexión directa P2P segura.',
    'call': 'Llamada segura',
    'new_chat': 'Nuevo canal seguro',
    'delete_chat': 'Borrar conversación',
    'block_peer': 'Bloquear ID Hex',
    'send_hint': 'Escribe mensaje encriptado...',
    'custom_sound': 'Tono exclusivo Padlock (Fijo)',
    'silent_mode': 'Modo silencioso',
    'notifications': 'Notificaciones',
    'sounds_desc': 'El sistema utiliza tonos de alerta exclusivos.',
    'app_lock': 'Bloqueo con código',
    'screen_security': 'Bloquear capturas de pantalla',
    'clear_keys': 'Purgar claves de encriptación',
    'keys_purged': 'Todas las claves de sesión han sido destruidas con seguridad.',
    'offline_contacts': 'Contactos activos P2P',
    'empty_contacts': 'No se encontraron contactos en la red local.',
  },
  'FR': {
    'chats': 'Chats',
    'contacts': 'Contacts',
    'settings': 'Paramètres',
    'profile': 'Profil',
    'search_hint': 'Rechercher base de données sécurisée...',
    'autodestruct': 'Autodestruction dans',
    'bio_label': 'Bio',
    'bio_text': 'Nœud crypté P2P / Sécurité de niveau militaire',
    'username_label': 'Nom d\'utilisateur',
    'copy_toast': 'ID copié dans le presse-papiers !',
    'qr_title': 'Code QR de confidentialité',
    'qr_desc': 'Scannez ce code pour établir une liaison directe P2P sécurisée.',
    'call': 'Appel sécurisé',
    'new_chat': 'Nouveau canal sécurisé',
    'delete_chat': 'Supprimer la conversation',
    'block_peer': 'Bloquer l\'ID Hex',
    'send_hint': 'Écrire un message crypté...',
    'custom_sound': 'Sonnerie exclusive Padlock (Fixe)',
    'silent_mode': 'Mode silencieux',
    'notifications': 'Notifications',
    'sounds_desc': 'Le système utilise des tonalités exclusives.',
    'app_lock': 'Verrouillage par code',
    'screen_security': 'Bloquer les captures d\'écran',
    'clear_keys': 'Purger les clés de cryptage',
    'keys_purged': 'Toutes les clés de session ont été détruites en toute sécurité.',
    'offline_contacts': 'Contacts actifs P2P',
    'empty_contacts': 'Aucun contact détecté sur le réseau local.',
  },
  'DE': {
    'chats': 'Chats',
    'contacts': 'Kontakte',
    'settings': 'Einstellungen',
    'profile': 'Profil',
    'search_hint': 'Sichere Datenbank durchsuchen...',
    'autodestruct': 'Selbstzerstörung in',
    'bio_label': 'Bio',
    'bio_text': 'P2P-verschlüsselter Knoten / Militärische Sicherheit',
    'username_label': 'Benutzername',
    'copy_toast': 'ID in die Zwischenablage kopiert!',
    'qr_title': 'Datenschutz-QR-Code',
    'qr_desc': 'Scannen Sie diesen Code, um eine sichere P2P-Verbindung aufzubauen.',
    'call': 'Sicherer Anruf',
    'new_chat': 'Neuer sicherer Kanal',
    'delete_chat': 'Konversation löschen',
    'block_peer': 'Hex-ID blockieren',
    'send_hint': 'Verschlüsselte Nachricht schreiben...',
    'custom_sound': 'Exklusiver Padlock-Ton (Fest)',
    'silent_mode': 'Lautlos-Modus',
    'notifications': 'Benachrichtigungen',
    'sounds_desc': 'Das System verwendet exklusive Signaltöne.',
    'app_lock': 'Code-Sperre',
    'screen_security': 'Bildschirmfotos blockieren',
    'clear_keys': 'Verschlüsselungsschlüssel löschen',
    'keys_purged': 'Alle Sitzungsschlüssel wurden sicher vernichtet.',
    'offline_contacts': 'Aktive P2P-Kontakte',
    'empty_contacts': 'Keine Kontakte im lokalen Netzwerk gefunden.',
  },
  'RU': {
    'chats': 'Чаты',
    'contacts': 'Контакты',
    'settings': 'Настройки',
    'profile': 'Профиль',
    'search_hint': 'Поиск в защищённой базе...',
    'autodestruct': 'Самоуничтожение через',
    'bio_label': 'О себе',
    'bio_text': 'P2P-узел с шифрованием / Защита военного уровня',
    'username_label': 'Имя пользователя',
    'copy_toast': 'ID скопирован в буфер обмена!',
    'qr_title': 'QR-код конфиденциальности',
    'qr_desc': 'Отсканируйте этот код для установления защищённого P2P-соединения.',
    'call': 'Защищённый звонок',
    'new_chat': 'Новый защищённый канал',
    'delete_chat': 'Удалить переписку',
    'block_peer': 'Заблокировать Hex ID',
    'send_hint': 'Введите зашифрованное сообщение...',
    'custom_sound': 'Эксклюзивный звук Padlock (фикс.)',
    'silent_mode': 'Беззвучный режим',
    'notifications': 'Уведомления',
    'sounds_desc': 'Система использует эксклюзивные зашифрованные сигналы.',
    'app_lock': 'Блокировка кодом',
    'screen_security': 'Блокировать снимки экрана',
    'clear_keys': 'Удалить ключи шифрования',
    'keys_purged': 'Все сеансовые ключи безопасно уничтожены.',
    'offline_contacts': 'Активные P2P-контакты',
    'empty_contacts': 'Контакты в локальной сети не обнаружены.',
  },
  'UK': {
    'chats': 'Чати',
    'contacts': 'Контакти',
    'settings': 'Налаштування',
    'profile': 'Профіль',
    'search_hint': 'Пошук у захищеній базі даних...',
    'autodestruct': 'Самознищення через',
    'bio_label': 'Про себе',
    'bio_text': "P2P-вузол із шифруванням / Захист військового рівня",
    'username_label': "Ім'я користувача",
    'copy_toast': 'ID скопійовано до буфера обміну!',
    'qr_title': 'QR-код конфіденційності',
    'qr_desc': "Скануйте цей код, щоб встановити захищене P2P-з'єднання.",
    'call': 'Захищений дзвінок',
    'new_chat': 'Новий захищений канал',
    'delete_chat': 'Видалити розмову',
    'block_peer': 'Заблокувати Hex ID',
    'send_hint': 'Введіть зашифроване повідомлення...',
    'custom_sound': 'Ексклюзивний звук Padlock (фікс.)',
    'silent_mode': 'Беззвучний режим',
    'notifications': 'Сповіщення',
    'sounds_desc': 'Система використовує ексклюзивні зашифровані сигнали.',
    'app_lock': 'Блокування кодом',
    'screen_security': 'Блокувати знімки екрана',
    'clear_keys': 'Видалити ключі шифрування',
    'keys_purged': 'Усі сеансові ключі безпечно знищено.',
    'offline_contacts': 'Активні P2P-контакти',
    'empty_contacts': 'Контактів у локальній мережі не знайдено.',
  },
  'ZH': {
    'chats': '聊天',
    'contacts': '联系人',
    'settings': '设置',
    'profile': '个人资料',
    'search_hint': '搜索安全数据库...',
    'autodestruct': '自动销毁时间',
    'bio_label': '简介',
    'bio_text': 'P2P 加密节点 / 军事级安全',
    'username_label': '用户名',
    'copy_toast': 'ID 已复制到剪贴板！',
    'qr_title': '隐私二维码',
    'qr_desc': '扫描此二维码以建立安全的点对点连接。',
    'call': '安全通话',
    'new_chat': '新建安全频道',
    'delete_chat': '清除对话',
    'block_peer': '屏蔽 Hex ID',
    'send_hint': '输入加密消息...',
    'custom_sound': 'Padlock 专属提示音（固定）',
    'silent_mode': '静音模式',
    'notifications': '通知',
    'sounds_desc': '系统使用专属加密提示音。',
    'app_lock': '密码锁定',
    'screen_security': '阻止屏幕截图',
    'clear_keys': '清除加密密钥',
    'keys_purged': '所有会话密钥已安全销毁。',
    'offline_contacts': '活跃的 P2P 联系人',
    'empty_contacts': '本地网络中未发现联系人。',
  },
  'KO': {
    'chats': '채팅',
    'contacts': '연락처',
    'settings': '설정',
    'profile': '프로필',
    'search_hint': '보안 데이터베이스 검색...',
    'autodestruct': '자동 삭제까지',
    'bio_label': '소개',
    'bio_text': 'P2P 암호화 노드 / 군사급 보안',
    'username_label': '사용자 이름',
    'copy_toast': 'ID가 클립보드에 복사되었습니다!',
    'qr_title': '개인정보 보호 QR 코드',
    'qr_desc': '이 코드를 스캔하여 안전한 P2P 연결을 설정하세요.',
    'call': '보안 통화',
    'new_chat': '새 보안 채널',
    'delete_chat': '대화 삭제',
    'block_peer': 'Hex ID 차단',
    'send_hint': '암호화된 메시지 입력...',
    'custom_sound': 'Padlock 전용 알림음 (고정)',
    'silent_mode': '무음 모드',
    'notifications': '알림',
    'sounds_desc': '시스템은 전용 암호화 알림음을 사용합니다.',
    'app_lock': '비밀번호 잠금',
    'screen_security': '스크린샷 차단',
    'clear_keys': '암호화 키 삭제',
    'keys_purged': '모든 세션 키가 안전하게 삭제되었습니다.',
    'offline_contacts': '활성 P2P 연락처',
    'empty_contacts': '로컬 네트워크에서 연락처를 찾을 수 없습니다.',
  },
  'AR': {
    'chats': 'الدردشات',
    'contacts': 'جهات الاتصال',
    'settings': 'الإعدادات',
    'profile': 'الملف الشخصي',
    'search_hint': 'البحث في قاعدة البيانات الآمنة...',
    'autodestruct': 'التدمير الذاتي خلال',
    'bio_label': 'نبذة',
    'bio_text': 'عقدة مشفّرة نظير إلى نظير / حماية بمستوى عسكري',
    'username_label': 'اسم المستخدم',
    'copy_toast': 'تم نسخ المعرف إلى الحافظة!',
    'qr_title': 'رمز QR للخصوصية',
    'qr_desc': 'امسح هذا الرمز لإنشاء اتصال آمن نظير إلى نظير.',
    'call': 'مكالمة آمنة',
    'new_chat': 'قناة آمنة جديدة',
    'delete_chat': 'حذف المحادثة',
    'block_peer': 'حظر المعرف السداسي',
    'send_hint': 'اكتب رسالة مشفّرة...',
    'custom_sound': 'نغمة Padlock الحصرية (ثابتة)',
    'silent_mode': 'الوضع الصامت',
    'notifications': 'الإشعارات',
    'sounds_desc': 'يستخدم النظام نغمات مشفّرة حصرية.',
    'app_lock': 'قفل بالرمز',
    'screen_security': 'حظر لقطات الشاشة',
    'clear_keys': 'مسح مفاتيح التشفير',
    'keys_purged': 'تم إتلاف جميع مفاتيح الجلسة بأمان.',
    'offline_contacts': 'جهات اتصال نظير إلى نظير نشطة',
    'empty_contacts': 'لم يتم العثور على جهات اتصال في الشبكة المحلية.',
  },
  'TR': {
    'chats': 'Sohbetler',
    'contacts': 'Kişiler',
    'settings': 'Ayarlar',
    'profile': 'Profil',
    'search_hint': 'Güvenli veritabanında ara...',
    'autodestruct': 'Kendi kendini imha süresi',
    'bio_label': 'Biyografi',
    'bio_text': 'P2P Şifreli Düğüm / Askeri Düzeyde Güvenlik',
    'username_label': 'Kullanıcı Adı',
    'copy_toast': 'Kimlik panoya kopyalandı!',
    'qr_title': 'Gizlilik QR Kodu',
    'qr_desc': 'Güvenli bir P2P bağlantısı kurmak için bu kodu tarayın.',
    'call': 'Güvenli Arama',
    'new_chat': 'Yeni Güvenli Kanal',
    'delete_chat': 'Sohbeti Sil',
    'block_peer': 'Hex Kimliğini Engelle',
    'send_hint': 'Şifreli mesaj yaz...',
    'custom_sound': 'Özel Padlock Sesi (Sabit)',
    'silent_mode': 'Sessiz Mod',
    'notifications': 'Bildirimler',
    'sounds_desc': 'Sistem özel şifreli tonlar kullanır.',
    'app_lock': 'Kod Kilidi',
    'screen_security': 'Ekran Görüntülerini Engelle',
    'clear_keys': 'Şifreleme Anahtarlarını Temizle',
    'keys_purged': 'Tüm oturum anahtarları güvenli şekilde yok edildi.',
    'offline_contacts': 'Aktif P2P Kişileri',
    'empty_contacts': 'Yerel ağda hiçbir kişi bulunamadı.',
  },
};

class MainNavigationScreen extends StatefulWidget {
  final String currentLanguage;
  final Function(String) onLanguageChange;

  const MainNavigationScreen({
    super.key,
    required this.currentLanguage,
    required this.onLanguageChange,
  });

  @override
  State<MainNavigationScreen> createState() => _MainNavigationScreenState();
}

class _MainNavigationScreenState extends State<MainNavigationScreen> with WidgetsBindingObserver {
   final _storage = const FlutterSecureStorage();
   int _lastNotifiedTimestamp = 0;
  String _username = "Carregando...";
  int _currentIndex = 0;
  String _myPrivacyId = '';
  String _destructTime = '7 Days';

  bool _notificationsActive = true;
  bool _silentMode = false;
  bool _passcodeLock = false;
  bool _blockScreenshots = true;

  final List<Map<String, dynamic>> _chats = [];

  final List<Map<String, String>> _contacts = [];
@override
  void initState() {
    super.initState();
    
    PadlockNetwork.connect();
    WidgetsBinding.instance.addObserver(this);
    _generateNewId();
     _loadUsername(); // Chama a função para ler o nome
    _loadStoredData(); // Carrega os contactos e mensagens do cofre
    _notificationsActive = Hive.box('padlock_vault').get('notifications_enabled', defaultValue: true);
    _silentMode = !_notificationsActive;
    _initNotifications();
    _resetInactivityTimer();
    // Auto-destruição em tempo real: sem isto, uma mensagem só desaparecia
    // de facto na próxima vez que a app arrancasse - enquanto a app ficasse
    // aberta, ficava visível para sempre depois do temporizador chegar a "0s".
    _destructTimer = Timer.periodic(const Duration(seconds: 15), (_) => _purgeExpiredMessages());
// Gatilho Inteligente de Arranque: Espera o canal abrir e só depois pede as mensagens pendentes
    Timer.periodic(const Duration(milliseconds: 300), (timer) {
      if (_myPrivacyId.isNotEmpty && PadlockNetwork.channel != null) {
       PadlockNetwork.channel!.sink.add(jsonEncode({
              'type': 'register',
              'senderId': _myPrivacyId,
              'fcmToken': Hive.box('padlock_vault').get('my_fcm_token')
            }));
        timer.cancel(); // Mensagens pedidas com sucesso, desliga o motor de busca
      }
    });

    // 2. A REGRA DA DESCONFIANÇA (Cura para o "Ecrã Congelado")
    // Espera meio segundo para o Cofre (Hive) carregar os dados antigos,
    // e depois varre todos os contactos, forçando-os a cinzento/laranja
    // até que o servidor confirme quem está realmente vivo.
    Future.delayed(const Duration(milliseconds: 500), () {
      if (mounted) {
        setState(() {
          for (var contact in _contacts) {
            contact['status'] = 'Aguardar...'; // Pode ser 'Offline', como preferires
          }
        });
      }
    });
    // Escuta as mensagens do WebSocket para detetar pedidos de contacto
    try {
      PadlockNetwork.messageHub.stream.listen((message) async {
              final data = jsonDecode(message);

              if (data['type'] == 'contact_request') {
                final String senderId = data['senderId'];
                // 1. Apanha a Chave Pública do amigo do outro lado da rede
                final String? senderPubKey = data['publicKey']; 
                
                // Vai dar ERRO VERMELHO aqui! Ignora e avança, vamos consertar a seguir.
                mostrarPedidoDeConexao(senderId, senderPubKey);
              } 
              else if (data['action'] == 'call_candidate') {
        PadlockNetwork.earlyCandidates.add(data);
      } else if (data['action'] == 'call_end') {
        FlutterCallkitIncoming.endAllCalls();
        PadlockNetwork.emChamada = false;
      } else if (data['type'] == 'wipe_chat') {
        final peerId = data['senderId'] ?? data['targetId'];
        for (var chat in _chats) {
          if (chat['id'] == peerId) {
            if (chat['messages'] != null) {
              chat['messages'].clear();
            }
            chat['msg'] = 'Nó Destruído';
          }
        }
        Hive.box('padlock_vault').put('chats', jsonEncode(_chats));
        setState(() {});
      }else if (data['type'] == 'delete_contact') {
          final peerId = data['targetId'];
          setState(() {
            // 1. Limpeza Forense dos Chats
            for (var c in _chats) {
              if (c['id'] == peerId && c['messages'] != null) {
                for (dynamic m in c['messages']) m['text'] = '0000000000000000';
                c['messages'].clear();
              }
            }
            // 2. Remove dos Chats e Contactos
            _chats.removeWhere((c) => c['id'] == peerId);
            _contacts.removeWhere((c) => c['id'] == peerId || c['name'] == peerId);
          });
          
          // 3. Queima as chaves no Cofre para cortar a ligação permanentemente
          final vault = Hive.box('padlock_vault');
          vault.put('contacts', jsonEncode(_contacts));
          vault.put('chats', jsonEncode(_chats));
          vault.delete('shared_secret_$peerId');
          vault.delete('private_key_$peerId');
        }
              else if (data['type'] == 'contact_accepted') {
                
                final String acceptedId = data['senderId'];
                final String? acceptedPubKey = data['publicKey'];

                // 2. O teu amigo aceitou. Recebes a chave pública dele e fechas a ponte!
                if (acceptedPubKey != null) {
                  try {
                    final vault = Hive.box('padlock_vault');
                    // --- INÍCIO DO ESCUDO ANTI-HACKER (TOFU) ---
String? chaveTrancada = vault.get('chave_publica_trancada_$acceptedId');

if (chaveTrancada == null) {
  // 1ª Vez: Confia e tranca a chave no cofre para sempre
  vault.put('chave_publica_trancada_$acceptedId', acceptedPubKey);
} else if (chaveTrancada != acceptedPubKey) {
  // ATAQUE DETETADO! A chave não é a mesma que estava no cofre.
  print('ALERTA CRÍTICO: Tentativa de interceção! Chave alterada.');
  ScaffoldMessenger.of(context).showSnackBar(
    const SnackBar(
      content: Text('ALERTA DE SEGURANÇA: Chave alterada. Ligação bloqueada!'),
      backgroundColor: Colors.red,
    ),
  );
  return; // O return corta tudo! A ligação morre aqui e o hacker não entra.
}
// --- FIM DO ESCUDO ---
                    final myPrivateKeyBase64 = vault.get('private_key_$acceptedId');
                    
                    if (myPrivateKeyBase64 != null) {
                      final algorithm = crypto.X25519();
                      final myPrivateKeyBytes = base64Decode(myPrivateKeyBase64);
                      // Extrai a tua chave privada guardada no cofre
                      final myPrivateKey = await algorithm.newKeyPairFromSeed(myPrivateKeyBytes);
                      
                      final theirPublicKeyBytes = base64Decode(acceptedPubKey);
                      final theirPublicKey = crypto.SimplePublicKey(theirPublicKeyBytes, type: crypto.KeyPairType.x25519);
                      
                      // 3. A MAGIA MATEMÁTICA: Funde as duas para criar o Segredo Absoluto
                      final sharedSecret = await algorithm.sharedSecretKey(
                        keyPair: myPrivateKey,
                        remotePublicKey: theirPublicKey,
                      );
                      final sharedSecretBytes = await sharedSecret.extractBytes();
                      final myPublicKeyBytes = (await myPrivateKey.extractPublicKey()).bytes;

                      // Guarda as duas chaves públicas para o Número de Segurança poder
                      // ser calculado deste lado também - faltava aqui (só existia no
                      // lado de quem ACEITA um pedido), por isso quem INICIA um pedido
                      // via "Adicionar Contacto" via sempre "Keys not available".
                      await vault.put('my_public_key_$acceptedId', base64Encode(myPublicKeyBytes));
                      await vault.put('their_public_key_$acceptedId', acceptedPubKey);

                      // 4. Tranca o Segredo e DESTROI a tua chave privada local (Anti-Forense)
                      await PadlockRatchet.establishChains(
  peerId: acceptedId,
  myId: _myPrivacyId,
  sharedSecretBytes: sharedSecretBytes,
  myHandshakePrivateKeyBytes: myPrivateKeyBytes,
  myHandshakePublicKeyBytes: myPublicKeyBytes,
  theirHandshakePublicKeyBytes: theirPublicKeyBytes,
);
                      // vault.delete('private_key_$acceptedId');
                    }
                  } catch (e) {
                    print('Erro na fundição da chave P2P: $e');
                  }
                }

                setState(() {
                  for (var contact in _contacts) {
                    if (contact['id'] == acceptedId) {
                      contact['status'] = 'Online';
                      contact['handshake'] = 'completed';
                    }
                  }
                });
                Hive.box('padlock_vault').put('contacts', jsonEncode(_contacts));
              }
              else if (data['action'] == 'call_offer') {
                // VERIFICAÇÃO TEMPORAL: Bloqueia a chamada se já passou mais de 60 segundos
        final int callTimestamp = data['timestamp'] ?? DateTime.now().millisecondsSinceEpoch;
        final int callAge = DateTime.now().millisecondsSinceEpoch - callTimestamp;
        
        if (callAge > 60000) {
          print('Chamada fantasma bloqueada (Tinha $callAge milissegundos de atraso)');
          return; // Aborta o ecrã de chamada aqui mesmo
          }
          if (PadlockNetwork.emChamada) {
          PadlockNetwork.channel?.sink.add(jsonEncode({'action': 'call_end', 'targetId': data['senderId']}));
          return;
        }
        
               if (mounted) {
  PadlockCallOverlay.show(ActiveCallScreen(
    local: t[Hive.box('padlock_vault').get('language') ?? 'EN'] ?? t['EN']!,
    recipientName: data['senderId'],
    targetId: data['senderId'],
    isIncoming: true,
    channel: PadlockNetwork.channel,
    incomingSdp: data['sdp'],
    acceptedViaCallKit: false,
    isVideo: data['isVideo'] == true,
  ));
}
}
              else if (data['type'] == 'secure_message') {
                
                if (data['senderId'] == Hive.box('padlock_vault').get('user_privacy_id')) return;
            final String peerId = data['senderId'] ?? data['targetId'];
// O SEGURANÇA: Se o ID não existir nos contactos aprovados, a mensagem morre aqui.
bool isContact = _contacts.any((c) => c['id'] == peerId || c['name'] == peerId);
if (!isContact) {
  return; // Bloqueia a execução. Não cria chat, não apita, apenas dropa o pacote.
}
            if (PadlockNetwork.chatAbertoAtualmente == peerId) {
              return;
            }
final int msgTimestamp = data['timestamp'] ?? 0;
    if (msgTimestamp > _lastNotifiedTimestamp) {
      _lastNotifiedTimestamp = msgTimestamp;
      showNotification('New Message', 'You have received an encrypted message.');
    }
            int chatIdx = _chats.indexWhere((c) => c['id'] == peerId);

        if (chatIdx == -1) {
      setState(() {
        _chats.insert(0, {'name': peerId, 'id': peerId, 'msg': '', 'time': 'Just Now', 'unread': 0, 'messages': []});
        chatIdx = 0;
      });
    }

        if (chatIdx != -1) {
             String decryptedText = '[Message not decrypted]';
            try {
              final chainIndex = data['chainIndex'] as int? ?? 0;
              final theirDhPub = data['dh'] as String?;
              final payloadParts = data['payload'].toString().split(':');
              if (payloadParts.length == 2) {
                final msgKeyBytes = await PadlockRatchet.receiveMessageKey(peerId, chainIndex, theirDhPub: theirDhPub);
                if (msgKeyBytes != null) {
                  final key = enc.Key(Uint8List.fromList(msgKeyBytes));
                  final iv = enc.IV.fromBase64(payloadParts[0]);
                  final encryptedData = enc.Encrypted.fromBase64(payloadParts[1]);
                  final encrypter = enc.Encrypter(enc.AES(key, mode: enc.AESMode.gcm));
                  decryptedText = encrypter.decrypt(encryptedData, iv: iv);
                }
              }
            } catch (e) {
              print('Erro ao decifrar: $e');
            }
                 
                 

              setState(() {
                final chat = _chats[chatIdx];
                if (chat['messages'] == null) {
                  chat['messages'] = <Map<String, dynamic>>[];
                }

                chat['messages'].add({
                  'text': decryptedText,
                  'isMe': false,
                  'status': 'delivered',
                  'timestamp': data['timestamp'],
                });

                chat['unread'] = (chat['unread'] ?? 0) + 1;
              });

              Hive.box('padlock_vault').put('chats', jsonEncode(_chats));
              Future.delayed(const Duration(seconds: 3), () => Hive.box('padlock_vault').compact());
              try {
               // html.Notification(
               // 'PADLOCK', 
               // body: 'New encrypted message received.',
               // );
              } catch (e) {
                print('Erro ao disparar pop-up de notificação: $e');
              }
         }
          }
          else if (data['type'] == 'secure_file') {
            if (data['senderId'] == Hive.box('padlock_vault').get('user_privacy_id')) return;
            final String peerId = data['senderId'] ?? data['targetId'];
            bool isContact = _contacts.any((c) => c['id'] == peerId || c['name'] == peerId);
            if (!isContact) return;

            String fileKind = 'file';
            try {
              final chainIndex = data['chainIndex'] as int? ?? 0;
              final theirDhPub = data['dh'] as String?;
              final payloadParts = data['payload'].toString().split(':');
              if (payloadParts.length == 2) {
                final msgKeyBytes = await PadlockRatchet.receiveMessageKey(peerId, chainIndex, theirDhPub: theirDhPub);
                if (msgKeyBytes != null) {
                  final key = enc.Key(Uint8List.fromList(msgKeyBytes));
                  final iv = enc.IV.fromBase64(payloadParts[0]);
                  final encryptedData = enc.Encrypted.fromBase64(payloadParts[1]);
                  final encrypter = enc.Encrypter(enc.AES(key, mode: enc.AESMode.gcm));
                  final innerJson = encrypter.decrypt(encryptedData, iv: iv);
                  final inner = jsonDecode(innerJson);
                  fileKind = inner['kind'] ?? 'file';
                  await VaultFilesStore.storeIncoming(
                    peerId: peerId,
                    fileName: inner['name'] ?? 'file',
                    fileKind: fileKind,
                    dataBase64: inner['data'],
                    timestamp: data['timestamp'] ?? DateTime.now().millisecondsSinceEpoch,
                  );
                }
              }
            } catch (e) {
              print('Erro ao decifrar ficheiro: $e');
            }

            int chatIdx = _chats.indexWhere((c) => c['id'] == peerId);
            if (chatIdx == -1) {
              setState(() {
                _chats.insert(0, {'name': peerId, 'id': peerId, 'msg': '', 'time': 'Just Now', 'unread': 0, 'messages': []});
                chatIdx = 0;
              });
            }
            final icon = fileKind == 'photo' ? '🖼️' : '📎';
            setState(() {
              final chat = _chats[chatIdx];
              chat['messages'] ??= <Map<String, dynamic>>[];
              chat['messages'].add({
                'text': '$icon Encrypted file received — open Secure Vault Files',
                'isMe': false,
                'status': 'delivered',
                'timestamp': data['timestamp'],
              });
              chat['unread'] = (chat['unread'] ?? 0) + 1;
            });
            Hive.box('padlock_vault').put('chats', jsonEncode(_chats));
          }
          else if (data['type'] == 'secure_voice') {
            if (data['senderId'] == Hive.box('padlock_vault').get('user_privacy_id')) return;
            final String peerId = data['senderId'] ?? data['targetId'];
            bool isContact = _contacts.any((c) => c['id'] == peerId || c['name'] == peerId);
            if (!isContact) return;

            String? audioBase64;
            try {
              final chainIndex = data['chainIndex'] as int? ?? 0;
              final theirDhPub = data['dh'] as String?;
              final payloadParts = data['payload'].toString().split(':');
              if (payloadParts.length == 2) {
                final msgKeyBytes = await PadlockRatchet.receiveMessageKey(peerId, chainIndex, theirDhPub: theirDhPub);
                if (msgKeyBytes != null) {
                  final key = enc.Key(Uint8List.fromList(msgKeyBytes));
                  final iv = enc.IV.fromBase64(payloadParts[0]);
                  final encryptedData = enc.Encrypted.fromBase64(payloadParts[1]);
                  final encrypter = enc.Encrypter(enc.AES(key, mode: enc.AESMode.gcm));
                  final innerJson = encrypter.decrypt(encryptedData, iv: iv);
                  audioBase64 = jsonDecode(innerJson)['data'];
                }
              }
            } catch (e) {
              print('Erro ao decifrar mensagem de voz: $e');
            }
            if (audioBase64 == null) return;

            int chatIdx = _chats.indexWhere((c) => c['id'] == peerId);
            if (chatIdx == -1) {
              setState(() {
                _chats.insert(0, {'name': peerId, 'id': peerId, 'msg': '', 'time': 'Just Now', 'unread': 0, 'messages': []});
                chatIdx = 0;
              });
            }
            setState(() {
              final chat = _chats[chatIdx];
              chat['messages'] ??= <Map<String, dynamic>>[];
              chat['messages'].add({
                'text': '🎤 Voice message',
                'audioBase64': audioBase64,
                'isMe': false,
                'status': 'delivered',
                'timestamp': data['timestamp'],
              });
              chat['unread'] = (chat['unread'] ?? 0) + 1;
            });
            Hive.box('padlock_vault').put('chats', jsonEncode(_chats));
          }
          else if (data['type'] == 'delete_message') {
        final int targetTimestamp = data['timestamp'];
        final String senderOfDelete = data['senderId'];
        
        setState(() {
          for (var chat in _chats) {
            if (chat['id'] == senderOfDelete || chat['id'] == data['targetId'] || chat['id'] == data['target']) {
              if (chat['messages'] != null) {
                for (var msg in chat['messages']) {
                  if (msg['timestamp'] == targetTimestamp) {
                    msg['text'] = '00000000000000000000000000000000'; // Destruição forense da RAM
                    if (msg['audioBase64'] != null) msg['audioBase64'] = ''; // idem para mensagens de voz
                  }
                }
                chat['messages'].removeWhere((msg) => msg['timestamp'] == targetTimestamp);
              }
            }
          }
        });
        
        // Salva a base de dados limpa no cofre Hive
        try {
          Hive.box('padlock_vault').put('chats', jsonEncode(_chats));
        } catch (e) {
          print('Erro ao atualizar cofre após delete: $e');
        }
      }
          // --- 1. LER A RESPOSTA DO SERVIDOR E PINTAR OS CADEADOS ---
          else if (data['type'] == 'peer_status') {
            final targetId = data['targetId'];
            final peerStatus = data['status']; // 'Online' ou 'Offline'
            
            setState(() {
              // Atualiza a cor nos Contactos
              for (var contact in _contacts) {
                if (contact['id'] == targetId) {
                  contact['status'] = peerStatus;
                }
              }
              // Atualiza a cor na lista de Chats
              for (var chat in _chats) {
                if (chat['id'] == targetId) {
                  chat['status'] = peerStatus;
                }
              }
            });
          }
        }); // Fim do listen do messageHub
            
       // --- 2. O RADAR: PERGUNTA AO RENDER A CADA 10 SEGUNDOS ---
    _statusTimer = Timer.periodic(const Duration(seconds: 10), (timer) {
      if (PadlockNetwork.channel == null) {
        PadlockNetwork.connect();
        Future.delayed(const Duration(seconds: 1), () {
          final myId = Hive.box('padlock_vault').get('user_privacy_id');
          if (myId != null && PadlockNetwork.channel != null) {
            PadlockNetwork.channel!.sink.add(jsonEncode({'type': 'register', 'senderId': myId}));
          }
        });
        return; 
      }
      if (PadlockNetwork.channel != null) {
        // 1. O Batimento Cardíaco para não deixar a net cair
        PadlockNetwork.channel!.sink.add(jsonEncode({'type': 'ping'}));

        if (PadlockNetwork.status.value == 'Online') {
          // 2. Pede o estado real dos amigos
          for (var contact in _contacts) {
            final idAlvo = contact['id'] ?? contact['name'];
            if (idAlvo != null && idAlvo.isNotEmpty) {
              PadlockNetwork.channel!.sink.add(jsonEncode({
                'type': 'check_status',
                'targetId': idAlvo
              }));
            }
          }
          
          // 3. O COFRE DE ESPERA: Dispara as mensagens que falharam antes!
          // --- 1.2 O SNIPER: Dispara ordens de destruição pendentes só quando o alvo fica Online ---
          final vault = Hive.box('padlock_vault');
          final pendingStr = vault.get('pending_kills');
          if (pendingStr != null) {
            List<dynamic> pendingKills = jsonDecode(pendingStr);
            List<dynamic> bulletsToKeep = [];
            
            for (var killSignal in pendingKills) {
               bool isTargetOnline = false;
               for (var c in _contacts) {
                 if (c['id'] == killSignal['targetId'] && c['status'] == 'Online') {
                   isTargetOnline = true; break;
                 }
               }
               
               if (isTargetOnline) {
                 PadlockNetwork.channel!.sink.add(jsonEncode(killSignal)); // Fogo!
               } else {
                 bulletsToKeep.add(killSignal); // Alvo offline. Guarda a bala no carregador.
               }
            }
            vault.put('pending_kills', jsonEncode(bulletsToKeep)); // Atualiza o carregador físico
          }
          final myId = Hive.box('padlock_vault').get('user_privacy_id');
          bool salvouAlguma = false;
          for (var chat in _chats) {
            if (chat['messages'] != null) {
              for (var msg in chat['messages']) {
                if (msg['isMe'] == true && msg['status'] == 'A aguardar...' && msg['payload'] != null) {
                  PadlockNetwork.channel!.sink.add(jsonEncode({
                    'type': 'secure_message',
                    'senderId': myId,
                    'targetId': chat['id'],
                    'payload': msg['payload'],
                    'chainIndex': msg['chainIndex'],
                    'dh': msg['dh'],
                    'timestamp': msg['timestamp'],
                  }));
                  msg['status'] = 'sent'; // Muda de 'Aguardar' para 'Enviado'
                  salvouAlguma = true;
                }
              }
            }
          }
          // Se encontrou mensagens presas e as enviou, atualiza o ecrã e grava!
          if (salvouAlguma && mounted) {
            setState((){});
            Hive.box('padlock_vault').put('chats', jsonEncode(_chats));
          }
        }
      }
    });

    } catch (e) {
      print('Erro ao escutar WebSocket: $e');
    }
  }
@override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _statusTimer?.cancel();
    _destructTimer?.cancel();
    super.dispose();
  }

  
  Timer? _gracePeriodTimer;
  Timer? _statusTimer; // O nosso Radar de Estado Online
  Timer? _inactivityTimer;
  Timer? _destructTimer;

  void _purgeExpiredMessages() {
    final now = DateTime.now().millisecondsSinceEpoch;
    bool changedAny = false;
    for (var chat in _chats) {
      if (chat['messages'] == null) continue;
      final destructTimeStr = chat['destructTime'] ?? '24h';
      int limitMillis = 24 * 60 * 60 * 1000;
      if (destructTimeStr == '1m') limitMillis = 60 * 1000;
      else if (destructTimeStr == '5m') limitMillis = 5 * 60 * 1000;
      else if (destructTimeStr == '1h') limitMillis = 60 * 60 * 1000;

      final before = (chat['messages'] as List).length;
      (chat['messages'] as List).removeWhere((msg) {
        final timestamp = msg['timestamp'] ?? now;
        final expired = (now - timestamp) > limitMillis;
        if (expired) {
          // Destruição forense: sobregrava antes de largar a referência.
          msg['text'] = '00000000000000000000000000000000';
          if (msg['audioBase64'] != null) msg['audioBase64'] = '';
        }
        return expired;
      });
      if ((chat['messages'] as List).length != before) changedAny = true;
    }
    if (changedAny) {
      if (mounted) setState(() {});
      Hive.box('padlock_vault').put('chats', jsonEncode(_chats));
    }
  }

  void _resetInactivityTimer() {
    _inactivityTimer?.cancel();
   _inactivityTimer = Timer(const Duration(minutes: 15), () {
      print('Sessão de 15 Minutos expirada. A forçar Logout.');
      if (PadlockNetwork.emChamada == true) return;
      _logout();
    });
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused) {
      // Deixa o túnel livre. Não corta a ligação para receberes mensagens em segundo plano.
    }
    else if (state == AppLifecycleState.resumed) {
      // 2. Acordou. Liga a mangueira.
      PadlockNetwork.connect();

      // 3. Registo Inteligente: Tenta registar mal deteta que o canal está vivo
    Timer.periodic(const Duration(milliseconds: 300), (timer) {
      if (_myPrivacyId.isNotEmpty && PadlockNetwork.channel != null) {
        PadlockNetwork.channel!.sink.add(jsonEncode({
              'type': 'register',
              'senderId': _myPrivacyId,
              'fcmToken': Hive.box('padlock_vault').get('my_fcm_token'),
            }));
        timer.cancel(); // Registo feito, mata o temporizador para não gastar bateria
      }
    });
    }
  }
  
   Future<void> _loadUsername() async {
    // Lê o nome diretamente do Cofre Blindado
    final vault = Hive.box('padlock_vault');
    String? name = vault.get('username');
    setState(() {
      _username = name ?? "Utilizador";
    });
  }

  Future<void> _loadStoredData() async {
    // 1. Liga-se ao cofre blindado que destrancámos na memória do chip ao abrir a app
final vault = Hive.box('padlock_vault');

// 2. Extrai os dados em total segurança (já decifrados pela chave AES do Hive)
String? contactsData = vault.get('contacts');
String? chatsData = vault.get('chats');

    setState(() {
      if (contactsData != null) {
        List<dynamic> decodedContacts = jsonDecode(contactsData);
        _contacts.clear();
        for (var item in decodedContacts) {
          _contacts.add(Map<String, String>.from(item));
        }
      }
      if (chatsData != null) {
        List<dynamic> decodedChats = jsonDecode(chatsData);
        _chats.clear();
        final now = DateTime.now().millisecondsSinceEpoch;
        
        for (var chat in decodedChats) {
          if (chat['messages'] != null) {
            final destructTimeStr = chat['destructTime'] ?? '24h';
            int limitMillis = 24 * 60 * 60 * 1000;
            if (destructTimeStr == '1m') limitMillis = 60 * 1000;
            else if (destructTimeStr == '5m') limitMillis = 5 * 60 * 1000;
            else if (destructTimeStr == '1h') limitMillis = 60 * 60 * 1000;
            else if (destructTimeStr == '24h') limitMillis = 24 * 60 * 60 * 1000;

            // Remove mensagens caducadas ANTES de mostrar o ecrã
            (chat['messages'] as List).removeWhere((msg) {
              final timestamp = msg['timestamp'] ?? now;
              return (now - timestamp) > limitMillis;
            });
          }
          _chats.add(Map<String, dynamic>.from(chat));
        }
      }
    });
  }
 Future<void> _initNotifications() async {
    // Notificações nativas Android serão geridas pelo Firebase ou LocalNotifications
    print('Sistema de notificações nativo inicializado.');
  }
  
  
Future<void> _generateNewId() async {
  final vault = Hive.box('padlock_vault');
  String? savedId = vault.get('user_privacy_id');

    if (savedId != null && savedId.isNotEmpty) {
      setState(() {
        _myPrivacyId = savedId;
      });
      PadlockNetwork.channel?.sink.add(jsonEncode({'type': 'register', 'senderId': savedId, 'fcmToken': Hive.box('padlock_vault').get('my_fcm_token')}));
      return;
    }

  final random = Random();
  final values = List<int>.generate(16, (i) => random.nextInt(256));
  final hex = values.map((b) => b.toRadixString(16).padLeft(2, '0')).join('').toUpperCase();
  final newId = '6432842A-${hex.substring(8, 16)}-${hex.substring(16, 24)}-${hex.substring(24, 32)}';

    // 3. Tranca o teu novo ID de privacidade no cofre AES-256
    vault.put('user_privacy_id', newId);
    
    setState(() {
      _myPrivacyId = newId;
    });
    PadlockNetwork.channel?.sink.add(jsonEncode({'type': 'register', 'senderId': newId, 'fcmToken': Hive.box('padlock_vault').get('my_fcm_token')}));
  }
Future<void> _logout() async {
    // Evita entrar em conflito com o bloqueio automático do Vault Files ou
    // do Crypto Vault, caso disparem quase ao mesmo tempo (ver comentário
    // em PadlockNetwork.isPerformingAutoLock) - o primeiro a chegar aqui
    // "ganha", os outros simplesmente não mexem no Navigator.
    if (PadlockNetwork.isPerformingAutoLock) return;
    PadlockNetwork.isPerformingAutoLock = true;
    // Se ainda houver uma chamada ligada (ou minimizada em bolha), fecha-a
    // primeiro - sem isto, a chamada continuava ativa em segundo plano
    // mesmo depois de "sair" do cofre, o que não faz sentido nenhum de
    // segurança (o cofre está trancado, mas a chamada encriptada continua).
    PadlockCallOverlay.hide();
    final vault = Hive.box('padlock_vault');
    vault.put('chats', jsonEncode(_chats));
    try {
      // Nunca deve travar a app à espera do disco - nalguns telemóveis
      // (relatado num Xiaomi) o botão parecia "não fazer nada", obrigando a
      // forçar o fecho da app. Com um limite de tempo, o pior caso passa a
      // ser "sair sem gravar os últimos segundos", nunca "ficar preso".
      await vault.flush().timeout(const Duration(seconds: 5));
      // Fecha mesmo o cofre - sem isto, Hive.openBox no LoginScreen devolveria
      // a mesma instância já aberta em memória e aceitaria QUALQUER frase,
      // sem voltar a validar a chave derivada de Argon2id.
      await vault.close().timeout(const Duration(seconds: 5));
    } catch (e) {
      print('Aviso: logout não conseguiu fechar o cofre a tempo: $e');
    }

    PadlockNetwork.disconnect();
    PadlockNetwork.isUnlocked = false;
    if (!mounted) {
      PadlockNetwork.isPerformingAutoLock = false;
      return;
    }
    Navigator.of(context).pushReplacement(
      MaterialPageRoute(builder: (context) => const LoginScreen()),
    );
    // Não repõe a flag para false aqui de propósito: esta rota vai ser
    // completamente substituída pelo LoginScreen, o que já cria uma
    // _MainNavigationScreenState nova (e outro temporizador de 15 min) da
    // próxima vez que se entrar - não há bloqueio nenhum para desbloquear.
  }
 // Função acionada pela rede P2P quando chega um pedido de nova conexão
  void mostrarPedidoDeConexao(String incomingId, String? senderPubKey) {
    showDialog(
      context: context,
      barrierDismissible: false, 
      builder: (context) => AlertDialog(
        backgroundColor: const Color(0xFF1A1A1A),
        shape: RoundedRectangleBorder(
          side: const BorderSide(color: Color(0xFF8B0000), width: 1.5),
          borderRadius: BorderRadius.circular(12),
        ),
        title: const Row(
          children: [
            Icon(Icons.security, color: Colors.white),
            SizedBox(width: 10),
            Text('Pedido de Conexão', style: TextStyle(color: Colors.white, fontSize: 18)),
          ],
        ),
        content: Text(
          'O ID de Privacidade "$incomingId" quer estabelecer um canal P2P encriptado de ponta-a-ponta consigo.\n\nAceitar?',
          style: const TextStyle(color: Colors.grey),
        ),
        actions: [
          TextButton(
            onPressed: () {
              Navigator.pop(context);
            },
            child: const Text('Rejeitar', style: TextStyle(color: Colors.grey)),
          ),
          TextButton(
            onPressed: () async {
              // 1. Gera o teu próprio par de chaves militares para responder
              final algorithm = crypto.X25519();
              final keyPair = await algorithm.newKeyPair();
              final myPublicKey = await keyPair.extractPublicKey();
              final myPrivateKey = await keyPair.extractPrivateKeyBytes();
              final myPublicKeyBase64 = base64Encode(myPublicKey.bytes);
              await Hive.box('padlock_vault').put('my_public_key_$incomingId', myPublicKeyBase64);
await Hive.box('padlock_vault').put('their_public_key_$incomingId', senderPubKey ?? '');

              // 2. Se o outro lado mandou a chave pública dele, cria o Segredo Absoluto já aqui!
              if (senderPubKey != null) {
                try {
                  final theirPublicKeyBytes = base64Decode(senderPubKey);
                  final theirPublicKey = crypto.SimplePublicKey(theirPublicKeyBytes, type: crypto.KeyPairType.x25519);
                  // --- INÍCIO DO ESCUDO ANTI-HACKER (TOFU) ---
final vaultSeguro = Hive.box('padlock_vault');
String? chaveTrancada = vaultSeguro.get('chave_publica_trancada_$incomingId');

if (chaveTrancada == null) {
  // 1ª Vez: Tranca a chave pública de quem está a pedir
  vaultSeguro.put('chave_publica_trancada_$incomingId', senderPubKey);
} else if (chaveTrancada != senderPubKey) {
  // ATAQUE DETETADO!
  print('ALERTA CRÍTICO: Chave de quem pede foi alterada.');
  ScaffoldMessenger.of(context).showSnackBar(
    const SnackBar(
      content: Text('ALERTA DE SEGURANÇA: Pedido bloqueado. Chave corrompida.'),
      backgroundColor: Colors.red,
    ),
  );
  return; // Bloqueia o processo, não gera a matemática e não aceita o contacto!
}
// --- FIM DO ESCUDO ---
                  // 3. A MAGIA MATEMÁTICA: Funde as chaves
                  final sharedSecret = await algorithm.sharedSecretKey(
                    keyPair: await algorithm.newKeyPairFromSeed(myPrivateKey),
                    remotePublicKey: theirPublicKey,
                  );
                  final sharedSecretBytes = await sharedSecret.extractBytes();

                  // 4. Guarda o segredo no cofre (a chave privada desaparece da RAM automaticamente!)
                  final vault = Hive.box('padlock_vault');
                  await vault.delete('shared_secret_$incomingId');
await PadlockRatchet.establishChains(
  peerId: incomingId,
  myId: _myPrivacyId,
  sharedSecretBytes: sharedSecretBytes,
  myHandshakePrivateKeyBytes: myPrivateKey,
  myHandshakePublicKeyBytes: myPublicKey.bytes,
  theirHandshakePublicKeyBytes: theirPublicKeyBytes,
);
                } catch (e) {
                  print('Erro a gerar segredo partilhado: $e');
                }
              }

              // 5. Envia o 'Sim' para a rede, com a tua Chave Pública à boleia!
              try {
                PadlockNetwork.channel?.sink.add(jsonEncode({
                  'type': 'contact_accepted',
                  'targetId': incomingId,
                  'senderId': _myPrivacyId,
                  'publicKey': myPublicKeyBase64, // <- Mandas a tua chave pública para ele fechar o cofre do lado dele
                }));
              } catch (e) {
                print('Erro ao enviar aceitação de contacto: $e');
              }

              setState(() {
                _contacts.add({
                  if (!_contacts.any((c) => c['id'] == incomingId))
                  'name': incomingId,
                  'id': incomingId,
                  'status': '',
                  'handshake': 'completed',
                });
                
                // Grava a lista de contactos permanentemente no cofre
              Hive.box('padlock_vault').put('contacts', jsonEncode(_contacts));
              });
              Hive.box('padlock_vault').put('contacts', jsonEncode(_contacts));
              if (context.mounted) {
                Navigator.pop(context);
              }
            },
            child: const Text('Aceitar', style: TextStyle(color: Colors.green)),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final local = t[widget.currentLanguage] ?? t['EN']!;
    int totalUnread = _chats.fold(0, (sum, chat) => sum + ((chat['unread'] ?? 0) as int));

    final List<Widget> screens = [
      ChatsScreen(
        local: local,
        destructTime: _destructTime,
        chats: _chats,
        onUpdateChats: () => setState(() {}),
      ),
      ContactsScreen(
        local: local,
        contacts: _contacts,
        onDeleteContact: (index) {
          showDialog(
            context: context,
            builder: (BuildContext context) {
              return AlertDialog(
                title: const Text('Apagar Contacto'),
                content: const Text('Tens a certeza de que pretendes remover este contacto?'),
                actions: [
                  TextButton(
                    onPressed: () => Navigator.pop(context),
                    child: const Text('Cancelar'),
                  ),
                  TextButton(
                   onPressed: () async {
              final cId = _contacts[index]['id'] ?? _contacts[index]['name'];
                    
                    if (cId != null && PadlockNetwork.channel != null) {
                      try { PadlockNetwork.channel!.sink.add(jsonEncode({'type': 'delete_contact', 'targetId': cId, 'senderId': Hive.box('padlock_vault').get('user_privacy_id')})); } catch (_) {}
                    }

                    setState(() {
                      for (var c in _chats) {
                        if ((c['id'] == cId || c['name'] == cId) && c['messages'] != null) {
                          for (var m in c['messages']) m['text'] = '0000000000000000';
                          c['messages'].clear();
                        }
                      }
                      
                      _chats.removeWhere((c) => c['id'] == cId || c['name'] == cId);
                      _contacts.removeWhere((c) => c['id'] == cId || c['name'] == cId);
                    });

                    final vault = Hive.box('padlock_vault');
await vault.put('contacts', jsonEncode(_contacts)); // Espera que grave os contactos
await vault.put('chats', jsonEncode(_chats));       // Espera que grave os chats
await PadlockRatchet.purgeContactKeys(cId ?? '');   // Destroi todo o estado do ratchet e o "pin" do TOFU

// O "KILL SWITCH": Força o telemóvel a raspar o disco físico na hora
await vault.flush();
await vault.compact(); // <--- TRITURADORA FORENSE: Obriga o disco físico a apagar o rasto das chaves antigas
if (context.mounted) {
  Navigator.pop(context);
}
},
                    child: const Text('Apagar', style: TextStyle(color: Colors.red)),
                  ),
                ],
              );
            },
          );
        },
        onEditContact: (index) {
          TextEditingController controller = TextEditingController(text: _contacts[index]['name']);
          showDialog(
            context: context,
            builder: (context) => AlertDialog(
              title: const Text('Editar Contacto'),
              content: TextField(
                controller: controller,
                decoration: const InputDecoration(labelText: 'Nome'),
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.pop(context),
                  child: const Text('Cancelar'),
                ),
                 TextButton(
            onPressed: () async {
              final novoNome = controller.text.trim();
              if (novoNome.isNotEmpty) {
                final contactoAntigo = _contacts[index];
                // Tenta apanhar o ID para ser 100% preciso na ligação, senão usa o nome antigo
                final idContacto = contactoAntigo['id'] ?? contactoAntigo['senderId'];
                final nomeAntigo = contactoAntigo['name'];

                setState(() {
                  // 1. Atualiza o nome na lista de Contactos
                  _contacts[index] = {
                    ...contactoAntigo,
                    'name': novoNome,
                  };

                  // 2. Percorre a lista de Mensagens e atualiza o nome lá também
                  for (var i = 0; i < _chats.length; i++) {
                    if ((idContacto != null && (_chats[i]['id'] == idContacto || _chats[i]['senderId'] == idContacto)) || 
                        _chats[i]['name'] == nomeAntigo) {
                      _chats[i] = {
                        ..._chats[i],
                        'name': novoNome,
                      };
                    }
                  }
                });

                // 3. Grava as duas listas permanentemente no cofre
                // 3. Grava as duas listas permanentemente no cofre AES-256 (invisível para extrações físicas)
    final vault = Hive.box('padlock_vault');
    vault.put('contacts', jsonEncode(_contacts));
    vault.put('chats', jsonEncode(_chats));
              }
              
              // Fecha o pop-up com segurança
              if (context.mounted) {
                Navigator.pop(context);
              }
            },
            child: const Text('Guardar'),
          ),

              ],
            ),
          );
        },
       onSelectContact: (contactName) {
          int existingIndex = _chats.indexWhere((c) => c['name'] == contactName);
          
          if (existingIndex == -1) {
            _chats.insert(0, {
              'name': contactName,
              'id': contactName,
              'msg': 'Secure channel established.',
              'time': 'Just Now',
              'unread': 0,
              'messages': [] // Deixa vazio para evitar erros de leitura fantasma
            });
            existingIndex = 0;
          } else {
            final chat = _chats.removeAt(existingIndex);
            _chats.insert(0, chat);
            existingIndex = 0;
          }
          
          // A REDE DE SEGURANÇA: Grava SEMPRE o cofre, seja chat novo ou antigo!
          Hive.box('padlock_vault').put('chats', jsonEncode(_chats));

          setState(() {
            _currentIndex = 0;
          });
          Navigator.push(
            context,
            MaterialPageRoute(
              builder: (context) => SingleChatScreen(
                local: local,
                chatData: _chats[existingIndex],
                destructTime: _destructTime,
                onUpdate: () => setState(() {}),
              ),
            ),
          );
        },
      ),
      SettingsScreen(
        local: local,
        currentLang: widget.currentLanguage,
        destructTime: _destructTime,
        notificationsActive: _notificationsActive,
        silentMode: _silentMode,
        passcodeLock: _passcodeLock,
        blockScreenshots: _blockScreenshots,
        onLangChange: widget.onLanguageChange,
        onDestructChange: (time) => setState(() => _destructTime = time),
        onNotificationsChange: (val) {
          setState(() {
            _notificationsActive = val;
            _silentMode = !val;
          });
          Hive.box('padlock_vault').put('notifications_enabled', val);
        },
        onSilentChange: (val) {
          setState(() {
            _silentMode = val;
            _notificationsActive = !val;
          });
          Hive.box('padlock_vault').put('notifications_enabled', !val);
        },
        onPasscodeChange: (val) => setState(() => _passcodeLock = val),
        onScreenshotsChange: (val) => setState(() => _blockScreenshots = val),
      ),
      ProfileScreen(
        local: local,
        username: _username,
         onUpdateUsername: (newUsername) async {
          setState(() {
            _username = newUsername;
          });
         final vault = Hive.box('padlock_vault');
        vault.put('username', newUsername);
        },
        privacyId: _myPrivacyId,
        onRegenerate: _generateNewId,
      ),
    ];

     return Listener(
      // Faltava isto: o Listener existia mas não tinha nenhum callback
      // ligado, por isso nunca reiniciava o temporizador de inatividade -
      // na prática, a "sessão de 15 minutos" disparava sempre 15 minutos
      // depois do login, sem ligar nenhuma se estavas mesmo a usar a app.
      onPointerDown: (_) => _resetInactivityTimer(),
      behavior: HitTestBehavior.translucent,
      child: Scaffold(
       appBar: AppBar(
        backgroundColor: Colors.transparent,
flexibleSpace: Container(
  decoration: const BoxDecoration(
    gradient: LinearGradient(
      begin: Alignment.topLeft,
      end: Alignment.bottomRight,
      colors: [
        Color(0xFF1e4d2b), // O verde suave
        Color(0xFF0a1a12), // O verde muito escuro/preto
      ],
    ),
  ),
),
elevation: 8, // Cria a densidade e a sombra (igual aos botões)
shadowColor: Colors.black, // Escurece a sombra para o efeito Matrix
centerTitle: true,
title: const Text(
  'PADLOCK',
  style: TextStyle(
    color: Color(0xFF00FF66), // Verde Neon
    fontSize: 13, 
    fontWeight: FontWeight.bold,
    letterSpacing: 2,
  ),
),
            
        actions: [
          
          PopupMenuButton<String>(
            color: const Color(0xFF0a1a12),
            shape: RoundedRectangleBorder(
              side: const BorderSide(color: Color(0xFF1e4d2b), width: 1.0),
              borderRadius: BorderRadius.circular(12),
            ),
            onSelected: (value) {
              if (value == 'logout') {
                _logout();
              }
               if (value == 'idioma') {
           showDialog(
            context: context,
            builder: (context) => AlertDialog(
              title: Text(t[widget.currentLanguage]?['language'] ?? 'Idioma / Language'),
              content: SizedBox(
                width: double.maxFinite,
                child: ListView(
                  shrinkWrap: true,
                  children: [
                    {'code': 'en', 'name': 'English'},
                    {'code': 'pt', 'name': 'Português'},
                    {'code': 'es', 'name': 'Español'},
                    {'code': 'fr', 'name': 'Français'},
                    {'code': 'de', 'name': 'Deutsch'},
                    {'code': 'it', 'name': 'Italiano'},
                    {'code': 'ru', 'name': 'Russo'},
                    {'code': 'zh', 'name': 'Chinês'},
                    {'code': 'ja', 'name': 'Japonês'},
                    {'code': 'ko', 'name': 'Coreano'},
                    {'code': 'ar', 'name': 'Árabe'},
                    {'code': 'hi', 'name': 'Hindi'},
                    {'code': 'nl', 'name': 'Holandês'},
                    {'code': 'pl', 'name': 'Polaco'},
                    {'code': 'tr', 'name': 'Turco'},
                    {'code': 'uk', 'name': 'Ucraniano'},
                  ].map((lang) => ListTile(
                    title: Text(lang['name']!),
                    onTap: () {
                      context.findAncestorStateOfType<_PadlockAppState>()?._changeLanguage(lang['code']!.toUpperCase());
                      Navigator.pop(context);
                    },
                  )).toList(),
                ),
              ),
            ),
          );
        }
            },
            itemBuilder: (BuildContext context) => [
              const PopupMenuItem(
                value: 'idioma',
                child: Text('Language', style: TextStyle(color: Colors.white)),
              ),
              const PopupMenuItem(
                value: 'logout',
                child: Text('Log Out', style: TextStyle(color: Color(0xFF00FF66), fontWeight: FontWeight.bold)),
              ),
            ],
          ),
        ],
      ),
      
      body: screens[_currentIndex],
       floatingActionButton: _currentIndex == 0
          ? FloatingActionButton(
              heroTag: "btn_chat",
              backgroundColor: const Color.fromARGB(255, 0, 153, 255),
              child: const Icon(Icons.chat),
               onPressed: () {
      // Abre uma caixa de diálogo rápida para iniciar uma nova conversa
      showDialog(
        context: context,
        builder: (context) => AlertDialog(
          backgroundColor: const Color(0xFF151515),
          shape: RoundedRectangleBorder(
            side: const BorderSide(color: Color(0xFF1e4d2b), width: 1.0),
            borderRadius: BorderRadius.circular(12),
          ),
          title: const Text("New Chat", style: TextStyle(color: Colors.white)),
          content: const Text("Start a new secure conversation?", style: TextStyle(color: Colors.grey)),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text("Cancel", style: TextStyle(color: Colors.grey)),
            ),
            TextButton(
              onPressed: () {
                Navigator.pop(context);
                setState(() {
                  _currentIndex = 1;
                });
              },
              child: const Text("Create", style: TextStyle(color: Color(0xFF00FF66))),
            ),
          ],
        ),
      );
    }, // Fecha o onPressed do FloatingActionButton
  ) // Fecha o FloatingActionButton
          : _currentIndex == 1
              ? FloatingActionButton(
                  heroTag: "btn_contact",
                  backgroundColor: const Color.fromARGB(255, 0, 153, 255),
                  child: const Icon(Icons.person_add),
                  onPressed: () {
                    TextEditingController controller = TextEditingController();
                    showDialog(
        context: context,
        builder: (context) => AlertDialog(
          backgroundColor: const Color(0xFF151515), // Fundo cinzento muito escuro (estilo Padlock)
          shape: RoundedRectangleBorder(
            side: const BorderSide(color: Color(0xFF1e4d2b), width: 1.0),
            borderRadius: BorderRadius.circular(12),
          ),
          title: const Text('Add Contact', style: TextStyle(color: Colors.white)),
          content: TextField(
            controller: controller,
            style: const TextStyle(color: Colors.black87), // Texto escuro para ler bem no fundo claro
            decoration: InputDecoration(
              hintText: 'Privacy ID',
              hintStyle: const TextStyle(color: Colors.black54),
              filled: true,
              fillColor: const Color(0xFFe4efe6), // O teu famoso "branco pérola / verde claro" do chat!
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(20), 
                borderSide: BorderSide.none
              ),
              contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
              suffixIcon: IconButton(
                icon: const Icon(Icons.qr_code_scanner, color: Color(0xFF1e4d2b)), // Ícone verde escuro para combinar
                onPressed: () async {
                  try {
                   // Sem pedir esta permissão explicitamente, nalguns telemóveis
                   // (relatado num Xiaomi/MIUI) a câmara simplesmente não aparece -
                   // fica um ecrã preto, sem erro nenhum a explicar porquê.
                   final camStatus = await Permission.camera.request();
                   if (!camStatus.isGranted) {
                     if (context.mounted) {
                       ScaffoldMessenger.of(context).showSnackBar(
                         const SnackBar(content: Text('Camera permission denied. Enable it in phone Settings > Apps > Padlock > Permissions.')),
                       );
                     }
                     return;
                   }
                   bool scanned = false; // A câmara deteta o mesmo código em vários frames
                   // seguidos - sem isto, cada frame chamava Navigator.pop outra vez,
                   // fechando também o diálogo "Add Contact" por trás do scanner.
                   await Navigator.push(
    context,
    MaterialPageRoute(
      builder: (context) => Scaffold(
        appBar: AppBar(title: const Text('Scan Privacy ID')),
        body: MobileScanner(
          onDetect: (capture) {
            if (scanned) return;
            final List<Barcode> barcodes = capture.barcodes;
            for (final barcode in barcodes) {
              if (barcode.rawValue != null) {
                scanned = true;
                controller.text = barcode.rawValue!;
                Navigator.pop(context);
                break;
              }
            }
          },
        ),
      ),
    ),
  );
                  } catch (e) {
                    print('Scan Error: $e');
                  }
                },
              ),
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Cancel', style: TextStyle(color: Colors.grey)),
            ),
            TextButton(
              onPressed: () async {
                final targetId = controller.text.trim();
                if (targetId.isNotEmpty) {
                  try {
                    // 1. Inicia o motor matemático de Nível Militar (Curve25519)
                    final algorithm = crypto.X25519();
                    
                    // 2. Gera um par de chaves ÚNICO só para esta conversa
                    final keyPair = await algorithm.newKeyPair();
                    final publicKey = await keyPair.extractPublicKey();
                    final privateKey = await keyPair.extractPrivateKeyBytes();
                    
                    // 3. Converte as chaves matemáticas em texto para podermos guardar e enviar
                    final publicKeyBase64 = base64Encode(publicKey.bytes);
                    final privateKeyBase64 = base64Encode(privateKey);
                    
                    // 4. TRANCA A CHAVE PRIVADA NO COFRE (Esta é a tua salvação, nunca sai daqui)
                    final vault = Hive.box('padlock_vault');
                    vault.put('private_key_$targetId', privateKeyBase64);

                    // 5. Envia o pedido à rede com a CHAVE PÚBLICA (O espião só vê esta parte inútil)
                    PadlockNetwork.channel?.sink.add(jsonEncode({
                      'type': 'contact_request',
                      'targetId': targetId,
                      'senderId': _myPrivacyId,
                      'publicKey': publicKeyBase64, // <- A chave pública entra em ação
                    }));
                  } catch (e) {
                    print('Erro na ignição criptográfica: $e');
                  }

                  // 6. Mantém a tua interface visual a funcionar perfeitamente
                   // Verifica se o ID já existe na lista antes de adicionar
bool jaExiste = _contacts.any((c) => c['id'] == targetId);
if (jaExiste) {
  Navigator.pop(context); // Fecha o pop-up
  ScaffoldMessenger.of(context).showSnackBar(
    const SnackBar(content: Text('Este contacto já está na tua lista!')),
  );
  return; // Para a execução aqui e não faz mais nada
} 
setState(() {
                    _contacts.add({
                      'name': targetId,
                      'id': targetId,
                      'status': 'A aguardar...',
                      'handshake': 'sent',
                    });
                  });
                  Navigator.pop(context);
                }
              },
                            child: const Text('Adicionar'),
                          ),
                        ],
                      ),
                    );
                  },
                )
              : null,
      bottomNavigationBar: Container(
        decoration: BoxDecoration(
          gradient: const LinearGradient(
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
            colors: [
              Color(0xFF1e4d2b), // Tom mais claro/reflexo do espelho
              Color(0xFF0a1a12), // Tom mais escuro/sombra
            ],
          ),
          border: Border(
            top: BorderSide(
              color: Colors.greenAccent.withValues(alpha: 0.3),
              width: 1.0,
            ),
          ),
          boxShadow: [
            BoxShadow(
              color: Colors.greenAccent.withValues(alpha: 0.2),
              blurRadius: 12,
              spreadRadius: 1,
              offset: const Offset(0, -3),
            ),
          ],
        ),
        child: BottomNavigationBar(
          backgroundColor: Colors.transparent, // Transparente para o gradiente espelho brilhar
          currentIndex: _currentIndex,
         
        type: BottomNavigationBarType.fixed,
        onTap: (index) {
          setState(() {
            _currentIndex = index;
          });
        },
        
        items: [
        BottomNavigationBarItem(
          icon: Stack(
      clipBehavior: Clip.none,
      children: [
        const Icon(Icons.chat_bubble_outline),
        if (totalUnread > 0)
          Positioned(
            right: -6,
            top: -6,
            child: Container(
              padding: const EdgeInsets.all(4),
              decoration: const BoxDecoration(
                color: const Color(0xFF00FF66),
                shape: BoxShape.circle,
              ),
              constraints: const BoxConstraints(minWidth: 16, minHeight: 16),
              child: Text(
                '$totalUnread',
                style: const TextStyle(color: Colors.white, fontSize: 10, fontWeight: FontWeight.bold),
                textAlign: TextAlign.center,
              ),
            ),
          ),
      ],
    ),
          activeIcon: const Icon(Icons.chat_bubble, color: Color(0xFF00FF66)),
          label: (() {
            final padlock = context.findAncestorStateOfType<_PadlockAppState>();
            final lang = padlock?._currentLanguage ?? 'EN';
            return (t[lang]?['chats'] as String?) ?? 'Chats';
          }()),
        ),
        BottomNavigationBarItem(
          icon: const Icon(Icons.people_outline),
          activeIcon: const Icon(Icons.chat_bubble, color: Color(0xFF00FF66)),
          label: (() {
            final padlock = context.findAncestorStateOfType<_PadlockAppState>();
            final lang = padlock?._currentLanguage ?? 'EN';
            return (t[lang]?['contacts'] as String?) ?? 'Contacts';
          }()),
        ),
        BottomNavigationBarItem(
          icon: const Icon(Icons.settings_outlined),
          activeIcon: const Icon(Icons.chat_bubble, color: Color(0xFF00FF66)),
          label: (() {
            final padlock = context.findAncestorStateOfType<_PadlockAppState>();
            final lang = padlock?._currentLanguage ?? 'EN';
            return (t[lang]?['settings'] as String?) ?? 'Settings';
          }()),
        ),
        BottomNavigationBarItem(
          icon: const Icon(Icons.person_outline),
          activeIcon: const Icon(Icons.chat_bubble, color: Color(0xFF00FF66)),
          label: (() {
            final padlock = context.findAncestorStateOfType<_PadlockAppState>();
            final lang = padlock?._currentLanguage ?? 'EN';
            return (t[lang]?['profile'] as String?) ?? 'Profile';
          }()),
        ),
  ],
          ),
        ), // <-- Fecha o Scaffold
     ));   // <-- Fecha o GestureDetector que abrimos na linha 962
      }
    }

// ----------------------------------------------------
// 1. CHATS SCREEN
// ----------------------------------------------------
class ChatsScreen extends StatelessWidget {
  final Map<String, String> local;
  final String destructTime;
  final List<Map<String, dynamic>> chats;
  final VoidCallback onUpdateChats;

  const ChatsScreen({
    super.key,
    required this.local,
    required this.destructTime,
    required this.chats,
    required this.onUpdateChats,
  });

  @override
  Widget build(BuildContext context) {
    final activeChats = chats.where((c) => c['status'] != 'Blocked').toList();
    final searchQuery = ValueNotifier<String>('');
   return Container(
          decoration: const BoxDecoration(
            image: DecorationImage(
              image: AssetImage('assets/fundo matrix.png'),
              fit: BoxFit.cover,
              colorFilter: ColorFilter.mode(Colors.black87, BlendMode.darken),
            ),
          ),
          child: Padding(
            padding: const EdgeInsets.all(15.0),
            child: Column(
        children: [
          TextField(
            onChanged: (val) => searchQuery.value = val,
            decoration: InputDecoration(
              hintText: local['search_hint'],
              prefixIcon: const Icon(Icons.search, color: Colors.grey),
              filled: true,
              fillColor: const Color(0xFF121212),
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(12),
                borderSide: BorderSide.none,
              ),
            ),
          ),
          const SizedBox(height: 15),
          Expanded(
          child: ValueListenableBuilder<String>(
        valueListenable: searchQuery,
        builder: (context, query, _) {
          final list = List<Map<String, dynamic>>.from(activeChats);
          if (query.trim().isNotEmpty) {
            final q = query.trim().toLowerCase();
            list.sort((a, b) {
              final aMatch = (a['name'] ?? '').toString().toLowerCase().contains(q);
              final bMatch = (b['name'] ?? '').toString().toLowerCase().contains(q);
              if (aMatch && !bMatch) return -1;
              if (!aMatch && bMatch) return 1;
              return 0;
            });
          }
          return RefreshIndicator(
        color: const Color(0xFF8B0000), // A cor vermelha do tema Padlock
        backgroundColor: const Color(0xFF1A1A1A),
        onRefresh: () async {
          // 1. O Botão de Pânico: Força a morte da ligação atual e cria uma nova
          PadlockNetwork.disconnect();
          PadlockNetwork.connect();
          
          // 2. Dá 1.5 segundos para o Render processar a nova entrada
          await Future.delayed(const Duration(milliseconds: 1500));
          
          // 3. Grita para o servidor pedindo as mensagens e os vistos que ficaram retidos
          final myId = Hive.box('padlock_vault').get('user_privacy_id');
          if (myId != null && PadlockNetwork.channel != null) {
            PadlockNetwork.channel?.sink.add(jsonEncode({
              'type': 'register',
              'senderId': myId,
              'fcmToken': Hive.box('padlock_vault').get('my_fcm_token'),
            }));
          }
          
          // 4. Força o ecrã a redesenhar as cores e as listas
          onUpdateChats(); 
        },
        child: ListView.builder(
          physics: const AlwaysScrollableScrollPhysics(), // Muito importante: permite puxar mesmo que tenhas apenas 1 chat na lista
            itemCount: list.length,
            itemBuilder: (context, index) {
              final chat = list[index];
                return GestureDetector(
                  onTap: () async {
                    chat['unread'] = 0; onUpdateChats();
                    await Navigator.push(
                    
                      context,
                      MaterialPageRoute(
                        builder: (context) => SingleChatScreen(
                          local: local,
                          chatData: chat,
                          destructTime: destructTime,
                          onUpdate: onUpdateChats,
                        ),
                      ),
                    );
                    
                  },
                  
                  child: Container(
                    margin: const EdgeInsets.only(bottom: 12),
                   
                decoration: BoxDecoration(
                  color: const Color(0xFF0a1a12),
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(color: const Color(0xFF1e4d2b), width: 1.0),
                ),
                    child: ListTile(
                      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 2),
                       leading: Stack(
          clipBehavior: Clip.none,
          children: [
            Container(
              width: 50,
              height: 50,
              decoration: BoxDecoration(
                color: const Color(0xFF1A1A1A),
                shape: BoxShape.circle,
                    border: Border.all(
                      color: (chat['status'] == 'Online') ? Colors.green : Colors.red,
                      width: 1.5,
                    ),
                  ),
                 child: Icon(
                Icons.lock,
                color: (chat['status'] == 'Online') ? Colors.green : Colors.red,
                size: 22,
              ),
            ),
            if ((chat['unread'] ?? 0) > 0)
            Positioned(
              top: -6,
              right: -6,
              child: Stack(
                alignment: Alignment.center,
                children: [
                  const Icon(
                    Icons.mail, 
                    color: Color.fromARGB(255, 252, 253, 252), 
                    size: 26,
                  ), // O envelope pequenino
                  Container(
          padding: const EdgeInsets.all(4),
          decoration: const BoxDecoration(
            color: Colors.red,
            shape: BoxShape.circle,
          ),
          child: Text(
            '${chat['unread']}',
            style: const TextStyle(
              color: Colors.white,
              fontSize: 10,
              fontWeight: FontWeight.bold,
            ),
          ),
        ),
      ], // Fecha a lista do Stack
    ), // Fecha o Stack do envelope
  ), // Fecha o Positioned
                  
          ],
        ),
                      title: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Expanded(
                child: Text(
                  chat['name'] ?? '',
                  style: const TextStyle(
                    fontWeight: FontWeight.bold, 
                    fontFamily: 'monospace',
                    color: Colors.white,
                  ),
                ),
              ),
              const SizedBox(width: 10),
              Text(
                chat['time'] ?? '',
                style: const TextStyle(color: Colors.grey, fontSize: 11),
              ),
            ],
          ),
                 subtitle: Padding(
        padding: const EdgeInsets.only(top: 6.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            
           
            const SizedBox(height: 4),
            
            Text('[Encrypted P2P Message]', maxLines: 1, overflow: TextOverflow.ellipsis, style: const TextStyle(color: Colors.lightBlueAccent)),
            const SizedBox(height: 4),
            Row(
              children: [
                const Icon(Icons.timer_outlined, size: 12, color: Colors.redAccent),
                const SizedBox(width: 4),
                Text('Auto-destructs in 24h', style: const TextStyle(color: Colors.redAccent, fontSize: 11)),
              ],
            ),
          ],
        ),
      ),      
trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            
            IconButton( 
  icon: const Icon(Icons.delete_forever, color: Color(0xFFFF1515), size: 28),
  onPressed: () {
    showDialog(
      context: context,
      builder: (context) {
        return AlertDialog(
              backgroundColor: const Color.fromARGB(255, 21, 21, 21),
              shape: RoundedRectangleBorder(
                side: const BorderSide(color: Color(0xFF1e4d2b), width: 1.0),
                borderRadius: BorderRadius.circular(12),
              ),
              title: const Text("Delete Chat", style: TextStyle(color: Colors.white)),
              content: const Text("Do you want to permanently delete this chat?", style: TextStyle(color: Color.fromARGB(255, 122, 241, 232))),
              actions: [
                TextButton(
                  onPressed: () => Navigator.pop(context),
                  child: const Text("Cancel", style: TextStyle(color: Color.fromARGB(255, 240, 206, 155))),
                ),
                TextButton(
                  onPressed: () {
                    Navigator.pop(context);
                    chats.removeAt(index);
                    // ATENÇÃO: Se tinhas mais alguma linha de código aqui (como um setState) para atualizar a lista, volta a colocá-la.
                  },
                  child: const Text("Delete", style: TextStyle(color: Color(0xFFFF1515))),
                ),
              ],
            );
      },
    );
  },
),
        ],),),),); // Fecha o ListTile
            },
      ),
    );
  },
),
          
        ),// Fecha o Expanded
      ], // Fecha os children da Column
    ), // Fecha a Column
   ));// Fecha o layout principal
  } // Fecha o método build
} // Fecha a classe ChatsScreen
// ----------------------------------------------------
// 1.5 SINGLE CHAT SCREEN
// ----------------------------------------------------
class SingleChatScreen extends StatefulWidget {
  final Map<String, String> local;
  final Map<String, dynamic> chatData;
  final String destructTime;
  final VoidCallback onUpdate;

  const SingleChatScreen({
    super.key,
    required this.local,
    required this.chatData,
    required this.destructTime,
    required this.onUpdate,
  });

  @override
  State<SingleChatScreen> createState() => _SingleChatScreenState();
}

class VoiceMessageBubble extends StatefulWidget {
  final String audioBase64;
  final bool isMe;
  const VoiceMessageBubble({super.key, required this.audioBase64, required this.isMe});

  @override
  State<VoiceMessageBubble> createState() => _VoiceMessageBubbleState();
}

class _VoiceMessageBubbleState extends State<VoiceMessageBubble> {
  final AudioPlayer _player = AudioPlayer();
  bool _isPlaying = false;

  @override
  void initState() {
    super.initState();
    _player.onPlayerComplete.listen((_) {
      if (mounted) setState(() => _isPlaying = false);
    });
  }

  @override
  void dispose() {
    _player.dispose();
    super.dispose();
  }

  Future<void> _toggle() async {
    if (_isPlaying) {
      await _player.stop();
      setState(() => _isPlaying = false);
    } else {
      await _player.play(BytesSource(base64Decode(widget.audioBase64)));
      setState(() => _isPlaying = true);
    }
  }

  @override
  Widget build(BuildContext context) {
    final color = widget.isMe ? Colors.white : Colors.black87;
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        IconButton(
          padding: EdgeInsets.zero,
          constraints: const BoxConstraints(),
          icon: Icon(_isPlaying ? Icons.stop_circle : Icons.play_circle_fill, color: color, size: 28),
          onPressed: _toggle,
        ),
        const SizedBox(width: 6),
        Text('Voice message', style: TextStyle(color: color, fontSize: 13)),
      ],
    );
  }
}

class _SingleChatScreenState extends State<SingleChatScreen> {
  final TextEditingController _msgController = TextEditingController();
  final ScrollController _scrollController = ScrollController();
  Timer? _destructionTimer;
  StreamSubscription? _chatSubscription;
  final AudioRecorder _voiceRecorder = AudioRecorder();
  bool _isRecording = false;
  String? _recordingPath;
Future<void> _processoMensagem = Future.value();
  @override
  void initState() {
    super.initState();
    PadlockNetwork.chatAbertoAtualmente = widget.chatData['id'];
    // --- METRALHADORA DE VISTOS BILATERAL ---
    void _forceReadReceipts() {
      if (PadlockNetwork.channel != null) {
        try {
          PadlockNetwork.channel!.sink.add(jsonEncode({
            'type': 'message_read',
            'senderId': Hive.box('padlock_vault').get('user_privacy_id'),
            'targetId': widget.chatData['id']
          }));
        } catch (e) {}
      }
    }

    // 1º Disparo: Imediato mal abres a porta do chat!
    _forceReadReceipts();
    
    // 2º Disparo: Passado 1.5 segundos (Rede de segurança à prova de falhas)
    Future.delayed(const Duration(milliseconds: 1500), _forceReadReceipts);

    // 3º Limpeza Local: Varre as tuas mensagens todas e assume-as como lidas
    if (widget.chatData['messages'] != null) {
      for (var msg in widget.chatData['messages']) {
        if (msg['isMe'] == false) {
          msg['status'] = 'read';
        }
      }
    }
    widget.chatData['unread'] = 0;
    
    // 4º Tranca o estado de leitura no cofre para as bolhas vermelhas apagarem logo
    final vault = Hive.box('padlock_vault');
      final String? chatsJson = vault.get('chats');
      if (chatsJson != null) {
        List<dynamic> allChats = jsonDecode(chatsJson);
        bool found = false;
        for (int i = 0; i < allChats.length; i++) {
          if (allChats[i]['id'] == widget.chatData['id']) {
            allChats[i] = widget.chatData;
            found = true;
            break;
          }
        }
        // SE NÃO ENCONTRAR O CHAT, CRIA-O!
        if (!found) allChats.insert(0, widget.chatData); 
        vault.put('chats', jsonEncode(allChats));
      } else {
        vault.put('chats', jsonEncode([widget.chatData]));
      }
    // Pede às listas de trás para se atualizarem silenciosamente
    Future.microtask(() => widget.onUpdate());
    // ----------------------------------------
    // Motor automático que corre a cada 1 segundo
    _destructionTimer = Timer.periodic(const Duration(seconds: 1), (timer) {
      if (mounted) {
        _checkExpiredMessages();
      }
    });
    // Escuta bilateral de mensagens recebidas via WebSocket P2P
    _chatSubscription = PadlockNetwork.messageHub.stream.listen((data) async {
     print('TESTE DE ENTRADA DO WEBSOCKET: $data');
     
      try {
        final decoded = jsonDecode(data);
        if (decoded['type'] == 'delete_message') {
              if (mounted) {
                setState(() {
                  if (widget.chatData['messages'] != null) {
                    final targetTimestamp = decoded['timestamp'];
                    // 1. Sobregravação forense na RAM (Destrói o rasto no telemóvel que recebe)
                    for (var i = 0; i < widget.chatData['messages'].length; i++) {
                      if (widget.chatData['messages'][i]['timestamp'] == targetTimestamp) {
                        widget.chatData['messages'][i]['text'] = '00000000000000000000000000000000';
                        if (widget.chatData['messages'][i]['audioBase64'] != null) widget.chatData['messages'][i]['audioBase64'] = '';
                      }
                    }
                    // 2. Limpeza local: Remove do ecrã
                    widget.chatData['messages'].removeWhere((msg) => msg['timestamp'] == targetTimestamp);
                  }
                });
                widget.onUpdate();
              }
              return;
            }

            if (decoded['type'] == 'wipe_chat') {
              if (mounted) {
                setState(() {
                  if (widget.chatData['messages'] != null) {
                    // 1. Sobregravação na RAM de todas as mensagens do chat
                    for (var i = 0; i < widget.chatData['messages'].length; i++) {
                      widget.chatData['messages'][i]['text'] = '00000000000000000000000000000000';
                      if (widget.chatData['messages'][i]['audioBase64'] != null) widget.chatData['messages'][i]['audioBase64'] = '';
                    }
                    // 2. Esvazia a lista totalmente
                    widget.chatData['messages'].clear();
                  }
                  widget.chatData['msg'] = 'Nó Destruído';
                });
                widget.onUpdate();
              }
              return;
            }
    if (decoded['type'] == 'update_timer') {
      if (mounted) {
        setState(() {
          widget.chatData['destructTime'] = decoded['time'];
        });
        widget.onUpdate();
        Hive.box('padlock_vault').put(widget.chatData['id'], widget.chatData);
      }
      return;
    }
        if (widget.chatData['status'] != 'Blocked' && decoded['type'] == 'secure_message') {
          if (decoded['senderId'] == Hive.box('padlock_vault').get('user_privacy_id')) return;
          _processoMensagem = _processoMensagem.then((_) async {
            
          if (mounted) {
            HapticFeedback.lightImpact();
SystemSound.play(SystemSoundType.click);
          // 1. Prepara a variável de segurança (se falhar, não mostra nada comprometedor)
          String decryptedText = await decryptSecureMessage(widget.chatData['id'], decoded);
       setState(() {
            (widget.chatData['messages'] as List).add(<String, Object>{
              'text': decryptedText,
              'isMe': false,
              'status': 'read',
              'timestamp': decoded['timestamp'],
            });
          });
          widget.onUpdate();
          // 1. Tranca a mensagem recebida na gaveta geral do cofre para não desaparecer
      final vault = Hive.box('padlock_vault');
      final String? chatsJson = vault.get('chats');
      if (chatsJson != null) {
        List<dynamic> allChats = jsonDecode(chatsJson);
        for (int i = 0; i < allChats.length; i++) {
          if (allChats[i]['id'] == widget.chatData['id']) {
            allChats[i] = widget.chatData;
            break;
          }
        }
        vault.put('chats', jsonEncode(allChats));
      }
      
      // 2. Empurra o ecrã automaticamente para baixo para não ficar debaixo do telefone!
      _scrollToBottom();
      Future.delayed(const Duration(seconds: 3), () => Hive.box('padlock_vault').compact());
          // 1. O SEGREDO: A Metralhadora dispara os vistos para a nova mensagem recebida!
        _forceReadReceipts();
        Future.delayed(const Duration(milliseconds: 1500), _forceReadReceipts);
        }
        });
      }
         

      // 2. RECEBER RECIBO P2P: Pinta os teus cadeados de azul!
      else if (decoded['type'] == 'message_read') {
        if (mounted) {
          setState(() {
            if (widget.chatData['messages'] != null) {
              for (var i = 0; i < widget.chatData['messages'].length; i++) {
                if (widget.chatData['messages'][i]['isMe'] == true) {
                  widget.chatData['messages'][i]['status'] = 'read';
                }
              }
            }
          });
          widget.onUpdate();
        }
     }
      // 3. RECEBER TEMPORIZADOR P2P: Sincroniza o relógio no outro telemóvel
      else if (decoded['type'] == 'update_timer') {
        if (mounted) {
          setState(() {
            widget.chatData['destructTime'] = decoded['time'];
          });
          widget.onUpdate();
        }
      }
      // Recebe o estado em tempo real dentro da conversa aberta
      else if (decoded['type'] == 'peer_status' && decoded['targetId'] == widget.chatData['id']) {
        if (mounted) {
          setState(() {
            widget.chatData['status'] = decoded['status'];
          });
          widget.onUpdate(); // Força as listas de trás a atualizarem-se também
        }
      }
     
    } catch (e) {
      print('Erro no fluxo de entrada P2P: $e');
    }
  });

  }

  @override
  void dispose() {
    _chatSubscription?.cancel();
    _destructionTimer?.cancel(); // Desliga o relógio ao sair do ecrã
    _voiceRecorder.dispose();
    PadlockNetwork.chatAbertoAtualmente = null;
    super.dispose();
  }


void _checkExpiredMessages() {
    if (widget.chatData['messages'] == null) return;

    final now = DateTime.now().millisecondsSinceEpoch;
    // Se a variável estiver vazia, o padrão automático passa a ser '24h'
    final destructTimeStr = widget.chatData['destructTime'] ?? '24h';

    int limitMillis = 24 * 60 * 60 * 1000; // Padrão base de 24 horas em milissegundos

    if (destructTimeStr == '1m') {
      limitMillis = 60 * 1000;
    } else if (destructTimeStr == '5m') {
      limitMillis = 5 * 60 * 1000;
    } else if (destructTimeStr == '1h') {
      limitMillis = 60 * 60 * 1000;
    } else if (destructTimeStr == '24h') {
      limitMillis = 24 * 60 * 60 * 1000;
    }

    bool apagouAlgumaCoisa = false;

    setState(() {
      widget.chatData['messages'].removeWhere((msg) {
        final timestamp = msg['timestamp'] ?? now;
        
        // Se o tempo que passou for maior que o limite escolhido, destrói!
       if ((now - timestamp) > limitMillis) {
  msg['text'] = '0000000000000000'; // Sobregravação de segurança anti-forense
  msg['read'] = true;
  apagouAlgumaCoisa = true;
  PadlockNetwork.channel?.sink.add(jsonEncode({
  'type': 'delete_message', 
  'timestamp': timestamp,
  'target': widget.chatData['id']
}));
  return true; // Aniquilação total do registo
}
        return false; // Mantém a mensagem
      });
    });

    // Só atualiza o ecrã e a base de dados se tiver efetivamente destruído alguma coisa
    if (apagouAlgumaCoisa) {
      widget.onUpdate();
   final vault = Hive.box('padlock_vault');
      final String? chatsJson = vault.get('chats');
      if (chatsJson != null) {
        List<dynamic> allChats = jsonDecode(chatsJson);
        bool found = false;
        for (int i = 0; i < allChats.length; i++) {
          if (allChats[i]['id'] == widget.chatData['id']) {
            allChats[i] = widget.chatData;
            found = true;
            break;
          }
        }
        // SE NÃO ENCONTRAR O CHAT, CRIA-O!
        if (!found) allChats.insert(0, widget.chatData); 
        vault.put('chats', jsonEncode(allChats));
      } else {
        vault.put('chats', jsonEncode([widget.chatData]));
      
      }
    }
  }
  

// 1. MOTOR DE DESTRUIÇÃO CORRIGIDO (Usa a impressão digital 'timestamp' em vez da posição)
  void _deleteMessage(int timestamp) {
    setState(() {
      // Destruição forense: Sobregrava os dados na RAM
      for (var msg in widget.chatData['messages']) {
        if (msg['timestamp'] == timestamp) {
          msg['text'] = '00000000000000000000000000000000';
          if (msg['audioBase64'] != null) msg['audioBase64'] = '';
        }
      }
    });

    // Sinal de Morte Bilateral para o outro telemóvel
    final killSignal = {
      'type': 'delete_message',
      'timestamp': timestamp,
      'senderId': Hive.box('padlock_vault').get('user_privacy_id'),
      'targetId': widget.chatData['id']
    };

    try {
      PadlockNetwork.channel?.sink.add(jsonEncode(killSignal));
    } catch (e) {
      print('Erro ao enviar sinal de destruição: $e');
    }

    // --- 1.2 FILA DE MORTE: Guarda a ordem no cofre ---
    final vault = Hive.box('padlock_vault');
    String? pendingStr = vault.get('pending_kills');
    List<dynamic> pendingKills = pendingStr != null ? jsonDecode(pendingStr) : [];
    pendingKills.add(killSignal);
    vault.put('pending_kills', jsonEncode(pendingKills));

    // Limpeza Local
    setState(() {
      widget.chatData['messages'].removeWhere((msg) => msg['timestamp'] == timestamp);
    });
    
    widget.onUpdate();
    
    // GRAVAÇÃO E TRITURAÇÃO FÍSICA NO DISCO
    
    final String? chatsJson = vault.get('chats');
    if (chatsJson != null) {
      List<dynamic> allChats = jsonDecode(chatsJson);
      for (int i = 0; i < allChats.length; i++) {
        if (allChats[i]['id'] == widget.chatData['id']) {
          allChats[i] = widget.chatData;
          break;
        }
      }
      vault.put('chats', jsonEncode(allChats));
      vault.compact(); // <--- Destrói fisicamente a versão antiga da mensagem no chip do telemóvel
    }
  
  }
String _getTimeLeft(int timestamp) {
    final limitStr = widget.chatData['destructTime'] ?? '24h';
    int limitMillis = 24 * 60 * 60 * 1000;
    if (limitStr == '1m') limitMillis = 60 * 1000;
    else if (limitStr == '5m') limitMillis = 5 * 60 * 1000;
    else if (limitStr == '1h') limitMillis = 60 * 60 * 1000;

    int timeLeft = (timestamp + limitMillis) - DateTime.now().millisecondsSinceEpoch;
    if (timeLeft <= 0) return '0s';

    if (timeLeft < 60000) return '${(timeLeft / 1000).floor()}s';
    if (timeLeft < 3600000) return '${(timeLeft / 60000).floor()}m';
    return '${(timeLeft / 3600000).floor()}h';
  }
  // 2. O MENU ESTILO TELEGRAM / SIGNAL (Aparece quando ficas a carregar na mensagem)
  void _showLongPressMenu(BuildContext context, Map<String, dynamic> msg) {
    showDialog(
      context: context,
      builder: (context) {
        return AlertDialog(
          backgroundColor: const Color(0xFF151515),
          shape: RoundedRectangleBorder(
            side: const BorderSide(color: Color(0xFF8B0000), width: 1.0),
            borderRadius: BorderRadius.circular(12),
          ),
          contentPadding: const EdgeInsets.symmetric(vertical: 10),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              ListTile(
                leading: const Icon(Icons.copy, color: Colors.white),
                title: const Text("Copiar Mensagem", style: TextStyle(color: Colors.white)),
                onTap: () {
                  Clipboard.setData(ClipboardData(text: msg['text']));
                  Navigator.pop(context); // Fecha o menu
                },
              ),
              const Divider(color: Colors.white10),
              ListTile(
                leading: const Icon(Icons.delete_outline, color: Colors.redAccent),
                title: const Text("Destruir Mensagem", style: TextStyle(color: Colors.redAccent)),
                onTap: () {
                  Navigator.pop(context); // Fecha o menu principal
                  
                  // Pergunta de confirmação antes de apagar de vez
                  showDialog(
                    context: context,
                    builder: (ctx) => AlertDialog(
                      backgroundColor: const Color(0xFF151515),
                      title: const Text("Destruição de Nó", style: TextStyle(color: Colors.white)),
                      content: const Text("Deseja destruir esta mensagem permanentemente em ambos os dispositivos?", style: TextStyle(color: Colors.grey)),
                      actions: [
                        TextButton(
                          onPressed: () => Navigator.pop(ctx),
                          child: const Text("Cancelar", style: TextStyle(color: Colors.grey)),
                        ),
                        TextButton(
                          onPressed: () {
                            Navigator.pop(ctx);
                            _deleteMessage(msg['timestamp']); // Executa a destruição!
                          },
                          child: const Text("Destruir", style: TextStyle(color: Colors.redAccent)),
                        ),
                      ],
                    ),
                  );
                },
              ),
            ],
          ),
        );
      },
    );
  }
Future<Map<String, String>> _encryptAES256(String plainText) async {
    final targetId = widget.chatData['id'];
    final result = await PadlockRatchet.nextSendKey(targetId);
    final key = enc.Key(Uint8List.fromList(result['key'] as List<int>));
    final iv = enc.IV.fromSecureRandom(16);
    final encrypter = enc.Encrypter(enc.AES(key, mode: enc.AESMode.gcm));
    final encrypted = encrypter.encrypt(plainText, iv: iv);
    return {
      'payload': '${iv.base64}:${encrypted.base64}',
      'chainIndex': (result['index'] as int).toString(),
      'dh': result['dh'] as String? ?? '',
    };
  }
Future<void> _sendPhotoFromChat() async {
    final targetId = widget.chatData['id'];
    final XFile? photo = await ImagePicker().pickImage(
      source: ImageSource.camera,
      imageQuality: 70,
      maxWidth: 1600,
    );
    if (photo == null) return;
    final bytes = await photo.readAsBytes();
    // Apaga o ficheiro temporário assim que os bytes estão em memória - a
    // foto nunca fica guardada em claro no telemóvel, nem toca a galeria.
    try { await File(photo.path).delete(); } catch (_) {}

    try {
      await sendEncryptedFile(targetId: targetId, fileBytes: bytes, fileName: 'photo.jpg', fileKind: 'photo');
      final currentTimestamp = DateTime.now().millisecondsSinceEpoch;
      setState(() {
        (widget.chatData['messages'] as List).add(<String, Object>{
          'text': '🖼️ Encrypted photo sent — view in Secure Vault Files',
          'isMe': true,
          'status': 'sent',
          'timestamp': currentTimestamp,
        });
        widget.chatData['msg'] = '🖼️ Photo';
        widget.chatData['time'] = 'Just Now';
      });
      widget.onUpdate();

      final vault = Hive.box('padlock_vault');
      final String? chatsJson = vault.get('chats');
      if (chatsJson != null) {
        List<dynamic> allChats = jsonDecode(chatsJson);
        bool found = false;
        for (int i = 0; i < allChats.length; i++) {
          if (allChats[i]['id'] == widget.chatData['id']) {
            allChats[i] = widget.chatData;
            found = true;
            break;
          }
        }
        if (!found) allChats.insert(0, widget.chatData);
        vault.put('chats', jsonEncode(allChats));
      } else {
        vault.put('chats', jsonEncode([widget.chatData]));
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Failed to send photo: $e')));
      }
    }
  }

  Future<void> _toggleVoiceRecording() async {
    if (_isRecording) {
      final path = await _voiceRecorder.stop();
      setState(() => _isRecording = false);
      if (path == null) return;
      try {
        final bytes = await File(path).readAsBytes();
        try { await File(path).delete(); } catch (_) {}

        await sendEncryptedVoice(targetId: widget.chatData['id'], audioBytes: bytes);
        final currentTimestamp = DateTime.now().millisecondsSinceEpoch;
        setState(() {
          (widget.chatData['messages'] as List).add(<String, Object>{
            'text': '🎤 Voice message',
            'audioBase64': base64Encode(bytes),
            'isMe': true,
            'status': 'sent',
            'timestamp': currentTimestamp,
          });
          widget.chatData['msg'] = '🎤 Voice message';
          widget.chatData['time'] = 'Just Now';
        });
        widget.onUpdate();

        final vault = Hive.box('padlock_vault');
        final String? chatsJson = vault.get('chats');
        if (chatsJson != null) {
          List<dynamic> allChats = jsonDecode(chatsJson);
          bool found = false;
          for (int i = 0; i < allChats.length; i++) {
            if (allChats[i]['id'] == widget.chatData['id']) {
              allChats[i] = widget.chatData;
              found = true;
              break;
            }
          }
          if (!found) allChats.insert(0, widget.chatData);
          vault.put('chats', jsonEncode(allChats));
        } else {
          vault.put('chats', jsonEncode([widget.chatData]));
        }
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Failed to send voice message: $e')));
        }
      }
    } else {
      if (!await _voiceRecorder.hasPermission()) return;
      _recordingPath = '${Directory.systemTemp.path}/padlock_voice_${DateTime.now().millisecondsSinceEpoch}.m4a';
      await _voiceRecorder.start(const RecordConfig(encoder: AudioEncoder.aacLc), path: _recordingPath!);
      setState(() => _isRecording = true);
    }
  }

Future<void> _sendMessage() async {
    if (_msgController.text.trim().isEmpty) return;

    final rawText = _msgController.text.trim();
    Map<String, String> encResult;
    try {
      encResult = await _encryptAES256(rawText);
    } catch (e) {
      // Sem isto, uma falha aqui (ex: canal cifrado por estabelecer com este
      // contacto) fazia o botão "Enviar" não fazer literalmente nada, sem
      // aviso nenhum - o texto ficava na caixa e parecia que a app tinha
      // travado.
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Could not send: no secure channel with this contact yet ($e). Try removing and re-adding them.')),
        );
      }
      return;
    }
final encryptedPayload = encResult['payload']!;
final chainIndex = int.parse(encResult['chainIndex']!);
final dhPub = encResult['dh']!;
    final currentTimestamp = DateTime.now().millisecondsSinceEpoch;
    final destId = widget.chatData['id'] ?? widget.chatData['peerId'] ?? widget.chatData['targetId'] ?? widget.chatData['contactId'] ?? widget.chatData.values.firstWhere((v) => v.toString().length > 30, orElse: () => '');
    
    // 1. VERIFICA SE O TUBO ESTÁ ABERTO ANTES DE CUSPIR A MENSAGEM
    bool isOnline = PadlockNetwork.status.value == 'Online' && PadlockNetwork.channel != null;

    if (isOnline) {
      try {
        PadlockNetwork.channel?.sink.add(jsonEncode({
          'type': 'secure_message',
          'senderId': Hive.box('padlock_vault').get('user_privacy_id'),
          'targetId': destId,
          'payload': encryptedPayload,
          'chainIndex': chainIndex,
          'dh': dhPub,
          'timestamp': currentTimestamp,
        }));
      } catch (e) {
        print('Erro ao enviar mensagem: $e');
      }
    }

    setState(() {
      widget.chatData['messages'].add({
        'text': rawText,
        'isMe': true,
        'timestamp': currentTimestamp,
        // 2. SE ESTIVER OFFLINE, FICA A AGUARDAR. SE ONLINE, MARCA LOGO ENVIADO.
        'status': isOnline ? 'sent' : 'A aguardar...',
        'payload': encryptedPayload, // Guarda o pacote já encriptado para o radar enviar depois
        'chainIndex': chainIndex,
        'dh': dhPub,
      });
      widget.chatData['msg'] = rawText;
      widget.chatData['time'] = 'Just Now';
    });

    _msgController.clear();
    widget.onUpdate();
    
   final vault = Hive.box('padlock_vault');
      final String? chatsJson = vault.get('chats');
      if (chatsJson != null) {
        List<dynamic> allChats = jsonDecode(chatsJson);
        bool found = false;
        for (int i = 0; i < allChats.length; i++) {
          if (allChats[i]['id'] == widget.chatData['id']) {
            allChats[i] = widget.chatData;
            found = true;
            break;
          }
        }
        // SE NÃO ENCONTRAR O CHAT, CRIA-O!
        if (!found) allChats.insert(0, widget.chatData); 
        vault.put('chats', jsonEncode(allChats));
      } else {
        vault.put('chats', jsonEncode([widget.chatData]));
      }
    _scrollToBottom();
    Future.delayed(const Duration(seconds: 3), () => Hive.box('padlock_vault').compact());
  }

 void _scrollToBottom() {
    Future.delayed(const Duration(milliseconds: 100), () {
      if (_scrollController.hasClients) {
        _scrollController.animateTo(
          0.0,
          duration: const Duration(milliseconds: 200),
          curve: Curves.easeOut,
        );
      }
    });
  }
  
   
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Colors.transparent, // Fica transparente para mostrar o degradê abaixo
elevation: 8,
shadowColor: Colors.black,
flexibleSpace: Container(
  decoration: const BoxDecoration(
    gradient: LinearGradient(
      begin: Alignment.topLeft,
      end: Alignment.bottomRight,
      colors: [
        Color(0xFF1e4d2b), // O verde suave
        Color(0xFF0a1a12), // O verde muito escuro/preto (efeito de sombra)
      ],
    ),
  ),
),


       
        title: Row(
          children: [
            Container(
              width: 35,
              height: 35,
              decoration: BoxDecoration(
                color: const Color(0xFF1A1A1A),
                shape: BoxShape.circle,
                border: Border.all(
                  color: widget.chatData['status'] == 'Online' ? Colors.greenAccent : const Color(0xFF8B0000), 
                  width: 1.2
                ),
              ), // BoxDecoration
              child: Icon(
                Icons.lock, 
                color: widget.chatData['status'] == 'Online' ? Colors.greenAccent : const Color(0xFF8B0000), 
                size: 16
              ),
              ),
            const SizedBox(width: 10),
          Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(widget.chatData['name'], style: const TextStyle(fontSize: 14, fontFamily: 'monospace', fontWeight: FontWeight.bold)),
                  
                  // TEXTO INTELIGENTE: Lê o estado real e muda a cor (Verde/Laranja/Vermelho)
                 Text(
  'Encrypted P2P Channel', 
  style: const TextStyle(
    fontSize: 10, 
    color: Colors.lightBlueAccent, 
    fontWeight: FontWeight.bold
  )
),
                  
                ],
              ),
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.phone, color: Colors.greenAccent),
            onPressed: () {
              PadlockCallOverlay.show(ActiveCallScreen(
                local: widget.local,
                recipientName: widget.chatData['name'],
                targetId: widget.chatData['id'],
                channel: PadlockNetwork.channel, // <--- A PEÇA QUE FALTAVA PARA O SINAL SAIR DO TELEMÓVEL!
              ));
            },
          ),
          IconButton(
            icon: const Icon(Icons.videocam, color: Colors.lightBlueAccent),
            onPressed: () {
              PadlockCallOverlay.show(ActiveCallScreen(
                local: widget.local,
                recipientName: widget.chatData['name'],
                targetId: widget.chatData['id'],
                channel: PadlockNetwork.channel,
                isVideo: true,
              ));
            },
          ),
          PopupMenuButton<String>(
  icon: const Icon(Icons.more_vert, color: Colors.grey),
  color: const Color(0xFF151515),
  onSelected: (val) {
    if (val == 'clear') {
              // 1. Sinal de Morte Global: Obriga o outro telefone a destruir o chat todo
              try {
                PadlockNetwork.channel?.sink.add(jsonEncode({
                  'type': 'wipe_chat',
                  'targetId': widget.chatData['id'],
                  'senderId': Hive.box('padlock_vault').get('user_privacy_id'),
                }));
              } catch (e) {
                print('Erro ao enviar sinal de aniquilação total: $e');
              }

              // 2. Destruição Forense (Sobregravação na RAM de todas as mensagens)
              setState(() {
                if (widget.chatData['messages'] != null) {
                  for (var i = 0; i < widget.chatData['messages'].length; i++) {
                    widget.chatData['messages'][i]['text'] = '00000000000000000000000000000000';
                    if (widget.chatData['messages'][i]['audioBase64'] != null) widget.chatData['messages'][i]['audioBase64'] = '';
                  }
                  widget.chatData['messages'].clear();
                }
                widget.chatData['msg'] = 'Nó Destruído';
              });
              
              widget.onUpdate();
              //Navigator.pop(context);
      } else if (val == 'block') {
          showDialog(
        context: context,
        builder: (context) => AlertDialog(
          backgroundColor: const Color(0xFF151515),
          title: const Text('Bloquear ID', style: TextStyle(color: Colors.white)),
          content: const Text('Deseja bloquear permanentemente este ID?', style: TextStyle(color: Colors.white70)),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Cancelar', style: TextStyle(color: Colors.grey)),
            ),
           TextButton(
                      onPressed: () async {
                        final cId = widget.chatData['id'];

                        setState(() {
                          // 1. Destruição forense total das mensagens na RAM
                          if (widget.chatData['messages'] != null) {
                            for (var i = 0; i < widget.chatData['messages'].length; i++) {
                              widget.chatData['messages'][i]['text'] = '0000000000000000';
                            }
                            widget.chatData['messages'].clear();
                          }
                          widget.chatData['status'] = 'Blocked';
                          widget.chatData['unread'] = 0; // Mata as bolhas vermelhas
                        });

                        // 2. Sinal de Morte Global para o trânsito (Servidor e Remetente)
                        try {
                          PadlockNetwork.channel?.sink.add(jsonEncode({
                            'type': 'wipe_chat',
                            'targetId': cId
                          }));
                        } catch (e) {
                          print('Erro ao enviar sinal de aniquilação no bloqueio: $e');
                        }

                        // 3. Queima todo o estado criptográfico (Obriga a novo pedido)
                        final vault = Hive.box('padlock_vault');
                        await PadlockRatchet.purgeContactKeys(cId);

                        // 4. Grava o bloqueio permanente no cofre local
      final String? chatsJson = vault.get('chats');
      if (chatsJson != null) {
        List<dynamic> allChats = jsonDecode(chatsJson);
        bool found = false;
        for (int i = 0; i < allChats.length; i++) {
          if (allChats[i]['id'] == widget.chatData['id']) {
            allChats[i] = widget.chatData;
            found = true;
            break;
          }
        }
        // SE NÃO ENCONTRAR O CHAT, CRIA-O!
        if (!found) allChats.insert(0, widget.chatData); 
        vault.put('chats', jsonEncode(allChats));
      } else {
        vault.put('chats', jsonEncode([widget.chatData]));
      }
                        Navigator.pop(context); // Fecha pop-up confirmação
                        Navigator.pop(context); // Fecha o chat e volta à lista principal
                      },
                      child: const Text('Bloquear', style: TextStyle(color: Colors.red)),
                    ),
          ],
        ),
      );
    }
    },
 itemBuilder: (context) => [
    PopupMenuItem(
            value: 'safety',
            onTap: () {
              final peerId = widget.chatData['id'] ?? widget.chatData['peerId'];
              final vault = Hive.box('padlock_vault');
              final myKey = vault.get('my_public_key_$peerId') ?? vault.get('user_public_key') ?? '';
              final theirKey = vault.get('their_public_key_$peerId') ?? vault.get('chave_publica_trancada_$peerId') ?? '';
              
              if (myKey.isEmpty || theirKey.isEmpty) {
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('Keys not available for this contact.', style: TextStyle(color: Colors.white)),
                  ),
                );
                return;
              }
              
              computeSafetyNumber(myKey, theirKey).then((number) {
                showDialog(
                  context: context,
                  builder: (ctx) => AlertDialog(
                    backgroundColor: Theme.of(context).canvasColor,
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(16),
                      side: BorderSide(color: Colors.greenAccent.withOpacity(0.5), width: 1),
                    ),
                    title: const Text(
                      'Safety Number', 
                      style: TextStyle(color: Colors.greenAccent, fontWeight: FontWeight.bold)
                    ),
                    content: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Text(
                          number,
                          style: const TextStyle(
                            color: Colors.greenAccent, 
                            fontFamily: 'monospace', 
                            fontSize: 13, 
                            letterSpacing: 1.2
                          ),
                          textAlign: TextAlign.center,
                        ),
                        const SizedBox(height: 20),
                        const Text(
                          'Make a secure call to this contact and read this number aloud. If they match on both devices, nobody is intercepting your conversation.',
                          style: TextStyle(color: Colors.white70, fontSize: 12),
                          textAlign: TextAlign.center,
                        ),
                      ],
                    ),
                    actions: [
                      TextButton(
                        onPressed: () => Navigator.pop(ctx), 
                        child: const Text('Close', style: TextStyle(color: Colors.greenAccent))
                      ),
                    ],
                  ),
                );
              });
            },
            child: const Text('Verify Safety Number', style: TextStyle(color: Colors.greenAccent)),
          ),
    PopupMenuItem(value: 'clear', child: Text(widget.local['delete_chat']!)),
    PopupMenuItem(value: 'block', child: Text(widget.local['block_peer']!)),
  ],
    ),  
        ]
        ),
      body: SafeArea( // Isto blinda a interface e força-a a subir quando o teclado aparece
        child: Column(
          children: [
              GestureDetector(
      onTap: () {
        showDialog(
          context: context,
          builder: (context) => AlertDialog(
            backgroundColor: const Color(0xFF151515),
            title: Text(widget.local['autodestruct'] ?? "Auto-Destruct", style: const TextStyle(color: Colors.white)),
            content: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                        ListTile(
                          title: const Text("1 Minute", style: TextStyle(color: Colors.white)),
                          onTap: () {
                            setState(() { widget.chatData['destructTime'] = '1m'; });
                            widget.onUpdate();
                            Hive.box('padlock_vault').put(widget.chatData['id'], widget.chatData);
                            try { PadlockNetwork.channel?.sink.add(jsonEncode({'type': 'update_timer', 'targetId': widget.chatData['id'], 'time': '1m'})); } catch (e) {}
                            Navigator.pop(context);
                          },
                        ),
                        ListTile(
                          title: const Text("5 Minutes", style: TextStyle(color: Colors.white)),
                          onTap: () {
                            setState(() { widget.chatData['destructTime'] = '5m'; });
                            widget.onUpdate();
                            Hive.box('padlock_vault').put(widget.chatData['id'], widget.chatData);
                            try { PadlockNetwork.channel?.sink.add(jsonEncode({'type': 'update_timer', 'targetId': widget.chatData['id'], 'time': '5m'})); } catch (e) {}
                            Navigator.pop(context);
                          },
                        ),
                        ListTile(
                          title: const Text("1 Hour", style: TextStyle(color: Colors.white)),
                          onTap: () {
                            setState(() { widget.chatData['destructTime'] = '1h'; });
                            widget.onUpdate();
                            Hive.box('padlock_vault').put(widget.chatData['id'], widget.chatData);
                            try { PadlockNetwork.channel?.sink.add(jsonEncode({'type': 'update_timer', 'targetId': widget.chatData['id'], 'time': '1h'})); } catch (e) {}
                            Navigator.pop(context);
                          },
                        ),
                        ListTile(
                          title: const Text("24 Hours", style: TextStyle(color: Colors.white)),
                          onTap: () {
                            setState(() { widget.chatData['destructTime'] = '24h'; });
                            widget.onUpdate();
                            Hive.box('padlock_vault').put(widget.chatData['id'], widget.chatData);
                            try { PadlockNetwork.channel?.sink.add(jsonEncode({'type': 'update_timer', 'targetId': widget.chatData['id'], 'time': '24h'})); } catch (e) {}
                            Navigator.pop(context);
                          },
                        ),
                      ],
            ),
          ),
        );
      },
      child: Container(
        color: const Color(0xFF880000).withValues(alpha: 0.15),
        padding: const EdgeInsets.symmetric(vertical: 6, horizontal: 12),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.timer_outlined, size: 13, color: Colors.redAccent),
            const SizedBox(width: 6),
            Text(
              '${widget.local['autodestruct']} ${widget.chatData['destructTime'] ?? "24h"}',
              style: const TextStyle(fontSize: 11, color: Colors.redAccent, fontWeight: FontWeight.bold),
            ),
          ],
        ),
      ),
    ),
          Expanded(
           child: Container(
            decoration: const BoxDecoration(
              image: DecorationImage(
                image: AssetImage('assets/fundo matrix.png'),
                fit: BoxFit.cover,
                colorFilter: ColorFilter.mode(Colors.black87, BlendMode.darken),
              ),
            ),
            child: ListView.builder(
              reverse: true,
              controller: _scrollController,
              padding: const EdgeInsets.all(15),
              itemCount: widget.chatData['messages'].length,
              itemBuilder: (context, index) {
                final m = widget.chatData['messages'].reversed.toList()[index];
                final isMe = m['isMe'] == true;
                return Align(
                  alignment: isMe ? Alignment.centerRight : Alignment.centerLeft,
                  child: GestureDetector(
                onLongPress: () => _showLongPressMenu(context, m),
                child: Container(
                    margin: const EdgeInsets.only(bottom: 10),
                    padding: const EdgeInsets.all(12),
                    constraints: BoxConstraints(maxWidth: MediaQuery.of(context).size.width * 0.75),
                    decoration: BoxDecoration(
                      color: isMe ? const Color(0xFF1e4d2b) : const Color(0xFFd8f3dc),
                      borderRadius: BorderRadius.only(
                        topLeft: const Radius.circular(12),
                        topRight: const Radius.circular(12),
                        bottomLeft: isMe ? const Radius.circular(12) : Radius.zero,
                        bottomRight: isMe ? Radius.zero : const Radius.circular(12),
                      ),
                      border: Border.all(color: isMe ? Colors.greenAccent.withValues(alpha: 0.4) : Colors.greenAccent.withValues(alpha: 0.2)),
                    ),
                    
                  child: Column(
  crossAxisAlignment: CrossAxisAlignment.end,
  children: [
    if (m['audioBase64'] != null)
      VoiceMessageBubble(audioBase64: m['audioBase64'], isMe: isMe)
    else
      Text(
      m['text'],
      style: TextStyle(
        color: m['text'] == '[Message not decrypted]' ? const Color(0xFFB00020) : (isMe ? Colors.white : Colors.black87),
        fontSize: m['text'] == '[Message not decrypted]' ? 11 : 14,
        fontStyle: m['text'] == '[Message not decrypted]' ? FontStyle.italic : FontStyle.normal,
      ),
    ),
    const SizedBox(height: 3),
    Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.av_timer, size: 11, color: Colors.redAccent),
    const SizedBox(width: 2),
    Text(
      _getTimeLeft(m['timestamp'] ?? DateTime.now().millisecondsSinceEpoch),
      style: const TextStyle(color: Colors.redAccent, fontSize: 9, fontWeight: FontWeight.bold),
    ),
    const SizedBox(width: 6),
                    Text(
                  DateTime.fromMillisecondsSinceEpoch(m['timestamp'] ?? DateTime.now().millisecondsSinceEpoch).toString().substring(11, 16),
                  style: TextStyle(color: isMe ? const Color(0xFFd8f3dc) : const Color(0xFF1e4d2b), fontSize: 9),
                ),
                const SizedBox(width: 5),
                    if (isMe) ...[
                      // Lógica APENAS para as tuas mensagens (Bolhas vermelhas)
                      Icon(
                        m['status'] == 'read' ? Icons.lock_open : Icons.lock,
                        size: 12,
                        color: m['status'] == 'read' ? Colors.lightBlueAccent : Colors.white60,
                      ),
                      if (m['status'] == 'delivered' || m['status'] == 'read') ...[
                        const SizedBox(width: 2),
                        Icon(
                          m['status'] == 'read' ? Icons.lock_open : Icons.lock,
                          size: 12,
                          color: m['status'] == 'read' ? Colors.lightBlueAccent : Colors.white60,
                        ),
                      ],
                    ],
                  ],
                ),
    ],
            ),
          ),
        ),
      );
    },
  ),
),
),
          Padding(
            padding: const EdgeInsets.all(10.0),
            child: Row(
              children: [
                CircleAvatar(
                  backgroundColor: const Color(0xFF1A1A1A),
                  child: IconButton(
                    icon: const Icon(Icons.camera_alt, color: Colors.lightBlueAccent, size: 18),
                    onPressed: widget.chatData['status'] == 'Blocked' ? null : _sendPhotoFromChat,
                  ),
                ),
                const SizedBox(width: 6),
                CircleAvatar(
                  backgroundColor: _isRecording ? Colors.redAccent : const Color(0xFF1A1A1A),
                  child: IconButton(
                    icon: Icon(_isRecording ? Icons.stop : Icons.mic, color: _isRecording ? Colors.white : Colors.lightBlueAccent, size: 18),
                    onPressed: widget.chatData['status'] == 'Blocked' ? null : _toggleVoiceRecording,
                  ),
                ),
                const SizedBox(width: 8),
                Expanded(
                    child: TextField(
                      controller: _msgController,
                      enabled: widget.chatData['status'] != 'Blocked',
                      style: const TextStyle(color: Colors.black87),
                      minLines: 1, // Começa com 1 linha
                      maxLines: 5, // Cresce até 5 linhas para baixo
                      keyboardType: TextInputType.multiline, // Permite quebras de linha
                      decoration: InputDecoration(
                        hintText: widget.local['send_hint'],
                        hintStyle: const TextStyle(color: Colors.black54),
                      filled: true,
                      fillColor: const Color(0xFFe4efe6),
                      border: OutlineInputBorder(borderRadius: BorderRadius.circular(20), borderSide: BorderSide.none),
                      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                    ),
                    onSubmitted: (val) => _sendMessage(),
                  ),
                ),
                const SizedBox(width: 8),
                CircleAvatar(
                  backgroundColor: const Color(0xFF1e4d2b),
                  child: IconButton(
                    icon: const Icon(Icons.send, color: Colors.white, size: 18),
                    onPressed: _sendMessage,
                  ),
                )
              ],
            ),
          )
      ],
    ), // Column
    ), // FECHA O SAFEAREA
    ); // FECHA O SCAFFOLD
  }
}

// ----------------------------------------------------
// 2. CONTACTS SCREEN
// ----------------------------------------------------
class ContactsScreen extends StatelessWidget {
  final Map<String, String> local;
  final List<Map<String, String>> contacts;
 final Function(String) onSelectContact;
  final Function(int) onDeleteContact;
  final Function(int) onEditContact;

  const ContactsScreen({
    super.key,
    required this.local,
    required this.contacts,
    required this.onSelectContact,
    required this.onDeleteContact,
    required this.onEditContact,
  });

  @override
  Widget build(BuildContext context) {
    final ValueNotifier<String> searchNotifier = ValueNotifier('');
    return Container(
      decoration: BoxDecoration(
        image: DecorationImage(
          image: AssetImage('assets/fundo matrix.png'),
          fit: BoxFit.cover,
          colorFilter: ColorFilter.mode(Colors.black87, BlendMode.darken),
        ),
      ),
      child: Padding(
        padding: const EdgeInsets.all(15.0),
        child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            local['offline_contacts']!,
            style: const TextStyle(fontSize: 18, fontWeight: FontWeight.bold, color: Colors.grey),
          ),
          const SizedBox(height: 15),
             Padding(
            padding: const EdgeInsets.only(bottom: 12.0),
            child: TextField(
              onChanged: (value) {
               searchNotifier.value = value;
              },
              style: const TextStyle(color: Colors.white),
              decoration: InputDecoration(
                hintText: 'Pesquisar contacto...',
                hintStyle: const TextStyle(color: Colors.grey),
                prefixIcon: const Icon(Icons.search, color: Colors.grey),
                filled: true,
                fillColor: const Color(0xFF1A1A1A),
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(12),
                  borderSide: BorderSide.none,
                ),
              ),
            ),
          ),
         Expanded(
      child: ValueListenableBuilder<String>(
        valueListenable: searchNotifier,
        builder: (context, query, child) {
          final filteredContacts = List<Map<String, String>>.from(contacts);
          if (query.isNotEmpty) {
            filteredContacts.sort((a, b) {
              final aMatch = (a['name'] ?? '').toLowerCase().contains(query.toLowerCase()) ? 0 : 1;
              final bMatch = (b['name'] ?? '').toLowerCase().contains(query.toLowerCase()) ? 0 : 1;
              return aMatch.compareTo(bMatch);
            });
          }

          return filteredContacts.isEmpty
              ? Center(child: Text(local['empty_contacts']!, style: const TextStyle(color: Colors.grey)))
              : ListView.builder(
                  itemCount: filteredContacts.length,
                  itemBuilder: (context, index) {
                    final contact = filteredContacts[index];
                      return Container(
                        margin: const EdgeInsets.only(bottom: 12),
                       decoration: BoxDecoration(
                  color: const Color(0xFF0a1a12),
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(color: const Color(0xFF1e4d2b), width: 1.0),
                ),
                        child: ListTile(
                          onLongPress: () => onDeleteContact(index),
                          leading: Container(
                            width: 45,
                            height: 45,
                            decoration: BoxDecoration(
              color: const Color(0xFF1A1A1A),
              shape: BoxShape.circle,
              border: Border.all(
                color: contact['status'] == 'Online' 
                    ? Colors.green 
                    : (contact['status'] == 'A aguardar...' ? Colors.orange : Colors.red),
                width: 1.5,
              ),
            ),
            child: Icon(
              Icons.lock, 
              color: contact['status'] == 'Online' 
                  ? Colors.green 
                  : (contact['status'] == 'A aguardar...' ? Colors.orange : Colors.red),
              size: 18,
            ),
                          ),
                          title: Text(contact['name']!, style: const TextStyle(fontFamily: 'monospace', fontWeight: FontWeight.bold)),
                          subtitle: const Text(
  'Encrypted P2P Contact',
  style: TextStyle(
    color: Colors.lightBlueAccent, 
    fontSize: 12,
    fontWeight: FontWeight.bold
  ),
),
                          trailing: IconButton(
          icon: const Icon(Icons.edit, color: Color(0xFF00FF66)),
          onPressed: () => onEditContact(index),
        ),
                          onTap: () => onSelectContact(contact['name']!),
                        ),
                      );
                          },
                                                                                                                              
                      );
                    }
                  ),
                ),
        ],
            )));
          }
       }   
// ----------------------------------------------------
// 3. SETTINGS SCREEN (LIMPA, PREMIUM E BLINDADA)
// ----------------------------------------------------
class SettingsScreen extends StatelessWidget {
  final Map<String, String> local;
  final String currentLang;
  
  // Mantemos as variáveis no construtor para o MainNavigationScreen não dar erro,
  // mesmo as que passaram a ser regras automáticas do sistema.
  final String destructTime;
  final bool notificationsActive;
  final bool silentMode;
  final bool passcodeLock;
  final bool blockScreenshots;

  final Function(String) onLangChange;
  final Function(String) onDestructChange;
  final Function(bool) onNotificationsChange;
  final Function(bool) onSilentChange;
  final Function(bool) onPasscodeChange;
  final Function(bool) onScreenshotsChange;

  const SettingsScreen({
    super.key,
    required this.local,
    required this.currentLang,
    required this.destructTime,
    required this.notificationsActive,
    required this.silentMode,
    required this.passcodeLock,
    required this.blockScreenshots,
    required this.onLangChange,
    required this.onDestructChange,
    required this.onNotificationsChange,
    required this.onSilentChange,
    required this.onPasscodeChange,
    required this.onScreenshotsChange,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: const BoxDecoration(
        image: DecorationImage(
          image: AssetImage('assets/fundo matrix.png'),
          fit: BoxFit.cover,
          colorFilter: ColorFilter.mode(Colors.black87, BlendMode.darken),
        ),
      ),
      child: Column(
        children: [
          // CABEÇALHO VERDE ESPELHADO
          Container(
            width: double.infinity,
            padding: const EdgeInsets.symmetric(vertical: 14),
            decoration: BoxDecoration(
              gradient: const LinearGradient(
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
                colors: [
                  Color(0xFF1e4d2b), // O teu verde espelhado suave
                  Color(0xFF0a1a12),
                ],
              ),
              border: Border(bottom: BorderSide(color: Colors.greenAccent.withValues(alpha: 0.3), width: 1.5)),
              boxShadow: [
                BoxShadow(
                  color: Colors.greenAccent.withValues(alpha: 0.1),
                  blurRadius: 10,
                  offset: const Offset(0, 3),
                ),
              ],
            ),
            child: const Center(
              child: Text(
                'SETTINGS',
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 15,
                  fontWeight: FontWeight.bold,
                  letterSpacing: 3.0,
                  fontFamily: 'monospace',
                ),
              ),
            ),
          ),

          // LISTA DE CONFIGURAÇÕES
          Expanded(
            child: ListView(
              padding: const EdgeInsets.symmetric(horizontal: 15, vertical: 15),
              children: [
                _buildSectionTitle('Core Security Protocols', Colors.greenAccent),
                _buildInfoTile(Icons.shield, 'Military-Grade Encryption', 'AES-256-GCM and Curve25519 standard.'),
                _buildInfoTile(Icons.wifi_tethering, 'True Peer-to-Peer', 'Direct voice & data. Zero server routing.'),
                _buildInfoTile(Icons.timer_off, 'Forensic Auto-Destruct', 'All messages shred within 24 hours max.'),
                _buildInfoTile(Icons.phonelink_erase, 'Screenshot Protection', 'Screen capture is globally blocked across the app to prevent unauthorized data leaks.'),
                _buildInfoTile(Icons.lock_clock, 'Safe Timeout', 'App closes automatically after 15 minutes of use for your security. Login is required to resume. Active calls bypass this rule to maintain connection.'),
                
                const Divider(color: Colors.white10, height: 35),

                _buildSectionTitle('Padlock Premium', Colors.amber),
                _buildPremiumTile(context),

                const Divider(color: Colors.white10, height: 35),

                _buildSectionTitle('Help Center / How to Use', Colors.greenAccent),
                _buildHelpTile(
      context, 
      Icons.folder_copy_rounded, 
      'How to use Secure Vault Files?', 
      'To access this section, you must create a dedicated encrypted key. Whenever you open the vault, it will prompt you for this key to log in, working just like the app security login.\n\n'
      '• All photos taken directly within Padlock are saved here automatically.\n'
      '• Documents and photos sent by contacts to your ID are routed directly to this vault instead of normal chats. You will receive a notification alert that media was sent, and you must access it inside the vault to view.\n'
      '• Files remain 100% encrypted and secure until manually deleted, exported, or re-sent.'
    ),
                _buildHelpTile(context, Icons.person_add, 'How to add a contact?', 'Go to the "Contacts" tab, tap the blue (+) button, and either paste a Privacy ID or use the green QR scanner.'),
                _buildHelpTile(context, Icons.share, 'How to share my ID?', 'Go to the "Profile" tab. Tap "Copy ID" to paste it securely anywhere, or "QR Code" to let someone scan your screen.'),
                _buildHelpTile(context, Icons.edit, 'How to rename a contact?', 'In the "Contacts" tab, tap the Edit (pencil) icon next to any contact to change their display name.'),
                _buildHelpTile(context, Icons.person_remove, 'How to delete a contact?', 'In the "Contacts" tab, long-press on any contact. This will permanently delete them and shred the shared encryption keys.'),
                _buildHelpTile(context, Icons.delete_sweep, 'How to wipe a conversation?', 'Inside any active chat, tap the menu (three dots) in the top right corner and select "Wipe Conversation" to obliterate all messages on both devices.'),
                
                const Divider(color: Colors.white10, height: 35),

                _buildSectionTitle('App Preferences', Colors.greenAccent),
                ListTile(
                  leading: const Icon(Icons.language, color: Color(0xFF1e4d2b)),
                  title: const Text('App Language', style: TextStyle(color: Colors.white)),
                  subtitle: Text('Current: $currentLang', style: const TextStyle(color: Colors.grey, fontSize: 11)),
                  trailing: const Icon(Icons.chevron_right, color: Colors.grey),
                  onTap: () => _showLanguageDialog(context),
                ),
                SwitchListTile(
                  secondary: const Icon(Icons.notifications_active, color: Color(0xFF1e4d2b)),
                  title: const Text('Push Notifications', style: TextStyle(color: Colors.white)),
                  subtitle: const Text('System uses exclusive encrypted tones.', style: TextStyle(fontSize: 11, color: Colors.grey)),
                  value: notificationsActive,
                  activeTrackColor: const Color(0xFF1e4d2b),
                  onChanged: onNotificationsChange,
                ),
                SwitchListTile(
                  secondary: const Icon(Icons.volume_off, color: Color(0xFF1e4d2b)),
                  title: const Text('Silent Mode', style: TextStyle(color: Colors.white)),
                  subtitle: const Text('Mutes all incoming P2P alerts.', style: TextStyle(fontSize: 11, color: Colors.grey)),
                  value: silentMode,
                  activeTrackColor: const Color(0xFF1e4d2b),
                  onChanged: onSilentChange,
                ),

                const Divider(color: Colors.white10, height: 35),

                _buildSectionTitle('Panic Room', Colors.redAccent),
                ListTile(
                  leading: const Icon(Icons.warning_amber_rounded, color: Colors.redAccent, size: 30),
                  title: const Text('NUKE VAULT: PURGE & DESTROY EVERYTHING', style: TextStyle(color: Colors.redAccent, fontWeight: FontWeight.bold, fontSize: 14)),
                  subtitle: const Padding(
                    padding: EdgeInsets.only(top: 6.0),
                    child: Text('This action will permanently shred your Privacy ID, crypto funds, and all chats. It clears everything and sends you back to the activation screen.', style: TextStyle(color: Colors.grey, fontSize: 11, height: 1.4)),
                  ),
                  onTap: () {
                    showDialog(
                      context: context,
                      barrierDismissible: false,
                      builder: (ctx) => AlertDialog(
                        backgroundColor: const Color(0xFF151515),
                        shape: RoundedRectangleBorder(
                          side: const BorderSide(color: Colors.redAccent, width: 2.0),
                          borderRadius: BorderRadius.circular(12),
                        ),
                        title: const Row(
                          children: [
                            Icon(Icons.dangerous, color: Colors.redAccent),
                            SizedBox(width: 10),
                            Text('CRITICAL WARNING', style: TextStyle(color: Colors.redAccent, fontWeight: FontWeight.bold, fontSize: 16)),
                          ],
                        ),
                        content: const Text(
                          'Are you sure you want to NUKE the vault?\n\n'
                          '⚠️ WITHDRAW ALL CRYPTO FUNDS AND SAVE YOUR FILES BEFORE PROCEEDING.\n\n'
                          'This action is irreversible. The application will be wiped to a factory state.',
                          style: TextStyle(color: Colors.white70, height: 1.4),
                        ),
                        actions: [
                          TextButton(
                            onPressed: () => Navigator.pop(ctx),
                            child: const Text('CANCEL', style: TextStyle(color: Colors.grey)),
                          ),
                          TextButton(
                            onPressed: () async {
                              try {
                                final vault = Hive.box('padlock_vault');
                                await vault.clear();
                                await vault.compact();
                                await vault.close();

                                // O Secure Vault Files é um cofre à parte (código próprio) -
                                // "destruir tudo" tem de o apagar também, mesmo que nunca
                                // tenha sido destrancado nesta sessão.
                                if (Hive.isBoxOpen('padlock_vault_files')) {
                                  await Hive.box('padlock_vault_files').close();
                                }
                                await Hive.deleteBoxFromDisk('padlock_vault_files');
                                await VaultFilesKey.wipe();
                                VaultFilesKey.lock();

                                const storage = FlutterSecureStorage();
                                await storage.deleteAll();
                                await PadlockVaultKey.wipe();
                                PadlockNetwork.isUnlocked = false;

                                if (context.mounted) {
                                  Navigator.pushAndRemoveUntil(
                                    context,
                                    MaterialPageRoute(builder: (context) => const SetupScreen()),
                                    (Route<dynamic> route) => false,
                                  );
                                }
                              } catch (e) {
                                print('Erro ao triturar cofre: $e');
                              }
                            },
                            child: const Text('NUKE EVERYTHING', style: TextStyle(color: Colors.redAccent, fontWeight: FontWeight.bold)),
                          ),
                        ],
                      ),
                    );
                  },
                ),
                const SizedBox(height: 40),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSectionTitle(String title, Color color) {
    return Padding(
      padding: const EdgeInsets.only(left: 5.0, bottom: 15),
      child: Text(
        title.toUpperCase(),
        style: TextStyle(fontSize: 12, color: color, fontWeight: FontWeight.bold, letterSpacing: 1.2),
      ),
    );
  }

  Widget _buildInfoTile(IconData icon, String title, String desc) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 15.0),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(icon, color: const Color(0xFF00FF66), size: 20),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(title, style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 13)),
                const SizedBox(height: 4),
                Text(desc, style: const TextStyle(color: Colors.white60, fontSize: 11, height: 1.3)),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildPremiumTile(BuildContext context) {
    return ListTile(
      contentPadding: EdgeInsets.zero,
      leading: const Text('💎', style: TextStyle(fontSize: 24)),
      title: const Row(
        children: [
          Text('Secure Crypto Vault', style: TextStyle(color: Colors.lightBlueAccent, fontWeight: FontWeight.bold, fontSize: 15)),
          SizedBox(width: 8),
          Icon(Icons.lock, color: Colors.greenAccent, size: 16),
        ],
      ),
      subtitle: const Padding(
        padding: EdgeInsets.only(top: 4.0),
        child: Text('Maximum security storage for your digital assets.', style: TextStyle(color: Colors.white60, fontSize: 11)),
      ),
      trailing: const Icon(Icons.chevron_right, color: Colors.lightBlueAccent),
      onTap: () => openCryptoVault(context),
    );
  }

  Widget _buildHelpTile(BuildContext context, IconData icon, String question, String answer) {
    return ListTile(
      contentPadding: EdgeInsets.zero,
      leading: Icon(icon, color: Colors.lightBlueAccent),
      title: Text(question, style: const TextStyle(color: Colors.lightBlueAccent, fontSize: 13)),
      trailing: const Icon(Icons.chevron_right, color: Colors.grey),
      onTap: () {
        showDialog(
          context: context,
          builder: (ctx) => AlertDialog(
            backgroundColor: const Color(0xFF151515),
            shape: RoundedRectangleBorder(
              side: const BorderSide(color: Colors.lightBlueAccent, width: 1.0),
              borderRadius: BorderRadius.circular(12),
            ),
            title: Text(question, style: const TextStyle(color: Colors.white, fontSize: 15)),
            content: Text(answer, style: const TextStyle(color: Colors.white70, height: 1.4, fontSize: 13)),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(ctx),
                child: const Text('Got it', style: TextStyle(color: Colors.lightBlueAccent)),
              ),
            ],
          ),
        );
      },
    );
  }

  void _showLanguageDialog(BuildContext context) {
    final langs = [
      {'code': 'en', 'name': 'English'}, {'code': 'pt', 'name': 'Português'},
      {'code': 'es', 'name': 'Español'}, {'code': 'fr', 'name': 'Français'},
      {'code': 'de', 'name': 'Deutsch'}, {'code': 'ru', 'name': 'Русский'},
      {'code': 'uk', 'name': 'Українська'}, {'code': 'zh', 'name': '中文'},
      {'code': 'ko', 'name': '한국어'}, {'code': 'ar', 'name': 'العربية'},
      {'code': 'tr', 'name': 'Türkçe'},
    ];
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF151515),
        title: const Text('Select Language', style: TextStyle(color: Colors.white)),
        content: SizedBox(
          width: double.maxFinite,
          child: ListView.builder(
            shrinkWrap: true,
            itemCount: langs.length,
            itemBuilder: (context, index) {
              return ListTile(
                title: Text(langs[index]['name']!, style: const TextStyle(color: Colors.white70)),
                onTap: () {
                  final code = langs[index]['code']!.toUpperCase();
                  // onLangChange fica ligado a um callback vazio quando se chega
                  // aqui a partir do Login/Setup - por isso a app não estava
                  // mesmo a mudar de língua. Atualiza diretamente o estado da
                  // app (o mesmo mecanismo que já funcionava no ecrã de Perfil).
                  context.findAncestorStateOfType<_PadlockAppState>()?._changeLanguage(code);
                  onLangChange(code);
                  Navigator.pop(ctx);
                },
              );
            },
          ),
        ),
      ),
    );
  }
}
// ----------------------------------------------------
// 4. PROFILE SCREEN
// ----------------------------------------------------
class ProfileScreen extends StatelessWidget {
   final Map<String, String> local;
  final String privacyId;
  final String username;
  final VoidCallback onRegenerate;
  final Function(String) onUpdateUsername;

  const ProfileScreen({
    super.key,
    required this.local,
    required this.privacyId,
    required this.username,
    required this.onRegenerate,
    required this.onUpdateUsername,
  });


  void _showQrDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) {
        
          
      final padlock = context.findAncestorStateOfType<_PadlockAppState>();
      final lang = padlock?._currentLanguage ?? 'EN';
      final currentT = t[lang] ?? {};
      return AlertDialog(
          backgroundColor: const Color(0xFF121212),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(15)),
          title: Center(
            child: Text(
              currentT['qr_title']!,
              style: const TextStyle(fontWeight: FontWeight.bold, color: Colors.white),
            ),
          ),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                currentT['qr_desc']!,
                style: const TextStyle(color: Colors.grey, fontSize: 12),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 25),
              QrImageView(
          data: privacyId,
          version: QrVersions.auto,
          size: 160.0,
          backgroundColor: Colors.white,
          foregroundColor: Colors.black,
        ),
        
              Text(
                privacyId,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 11, color: Colors.redAccent, fontWeight: FontWeight.bold),
                textAlign: TextAlign.center,
              )
            ],
          ),
          actions: [
            Center(
              child: TextButton(
                onPressed: () => Navigator.pop(context),
                child: Text(currentT['close'] ?? 'Close', style: const TextStyle(color: Colors.white70)),
              ),
            )
          ],
        );
      },
    );
  }

  @override
Widget build(BuildContext context) {
  return Container(
    decoration: const BoxDecoration(
      image: DecorationImage(
        image: AssetImage('assets/fundo matrix.png'),
        fit: BoxFit.cover,
        colorFilter: ColorFilter.mode(Colors.black87, BlendMode.darken),
      ),
    ),
    child: SingleChildScrollView(
      child: Column(
        children: [
          Center(
            child: Container(
              width: 110,
              height: 110,
              decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  gradient: const LinearGradient(
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                    colors: [
                      Color(0xFF1e4d2b),
                      Color(0xFF0a1a12),
                    ],
                  ),
                  border: Border.all(
                    color: Colors.greenAccent.withValues(alpha: 0.5),
                    width: 1.5,
                  ),
                  boxShadow: [
                    BoxShadow(
                      color: Colors.greenAccent.withValues(alpha: 0.3),
                      blurRadius: 20,
                      spreadRadius: 2,
                      offset: const Offset(0, 4),
                    ),
                  ],
                ),
              child: ClipOval(
                child: Image.asset(
                  'assets/padlock-image.app.png',
                  fit: BoxFit.cover,
                ),
              ),
            ),
          ),
          const SizedBox(height: 15),
           GestureDetector(
          onTap: () {
            TextEditingController controller = TextEditingController(text: username);
            showDialog(
              context: context,
              builder: (context) => AlertDialog(
                title: const Text('Editar Nome'),
                content: TextField(
                  controller: controller,
                  decoration: const InputDecoration(labelText: 'Nome de Utilizador'),
                ),
                actions: [
                  TextButton(
                    onPressed: () => Navigator.pop(context),
                    child: const Text('Cancelar'),
                  ),
                  TextButton(
                    onPressed: () {
                      if (controller.text.trim().isNotEmpty) {
                        onUpdateUsername(controller.text.trim());
                      }
                      Navigator.pop(context);
                    },
                    child: const Text('Guardar'),
                  ),
                ],
              ),
            );
          },
          child: Container(
  width: 220,
  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
  decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(12),
        gradient: const LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            Color(0xFF1e4d2b),
            Color(0xFF0a1a12),
          ],
        ),
        border: Border.all(
          color: Colors.greenAccent.withValues(alpha: 0.35),
          width: 1.2,
        ),
        boxShadow: [
          BoxShadow(
            color: Colors.greenAccent.withValues(alpha: 0.2),
            blurRadius: 15,
            spreadRadius: 1,
            offset: const Offset(0, 4),
          ),
        ],
      ),
  child: Row(
    mainAxisAlignment: MainAxisAlignment.center,
    children: [
      Flexible(
        child: Text(
          username,
          overflow: TextOverflow.ellipsis,
          style: const TextStyle(fontSize: 18, fontWeight: FontWeight.bold, color: Colors.white),
        ),
      ),
      const SizedBox(width: 10),
      const Icon(Icons.edit, size: 16, color: Colors.greenAccent),
    ],
  ),
), // Container
        ),
          ValueListenableBuilder<String>(
  valueListenable: PadlockNetwork.status,
  builder: (context, status, child) {
    Color statusColor = Colors.redAccent;
    if (status == 'Online') statusColor = Colors.greenAccent;
    if (status == 'Aguardar...') statusColor = Colors.orangeAccent;

    return Text(
      status.toLowerCase(),
      style: TextStyle(
        color: statusColor, 
        fontSize: 14, 
        fontWeight: FontWeight.bold,
      ),
    );
  },
),
          const SizedBox(height: 25),

         Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              _buildActionButton(Icons.qr_code, 'QR Code', () => _showQrDialog(context), color: Colors.lightBlueAccent),
              _buildActionButton(Icons.copy, 'Copy ID', () {
                Clipboard.setData(ClipboardData(text: privacyId));
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(content: Text(local['copy_toast']!)),
                );
              }),
              
              // NOVO BOTÃO: SECURE CRYPTO VAULT (Substitui o Regen)
              InkWell(
                onTap: () => openCryptoVault(context),
                borderRadius: BorderRadius.circular(12),
                child: Container(
                  width: 82,
                  height: 74,
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(12),
                    gradient: const LinearGradient(
                      begin: Alignment.topLeft,
                      end: Alignment.bottomRight,
                      colors: [
                        Color(0xFF1e4d2b), // O verde espelhado suave
                        Color(0xFF0a1a12), // Sombra escura
                      ],
                    ),
                    border: Border.all(
                      color: Colors.greenAccent.withValues(alpha: 0.35),
                      width: 1.2,
                    ),
                    boxShadow: [
                      BoxShadow(
                        color: Colors.greenAccent.withValues(alpha: 0.2),
                        blurRadius: 15,
                        spreadRadius: 1,
                        offset: const Offset(0, 4),
                      ),
                    ],
                  ),
                  child: const Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      // O Diamante gigante
                      Text('💎', style: TextStyle(fontSize: 22)), 
                      SizedBox(height: 2),
                      // O texto em Branco Pérola no fundo
                      Text(
                        'Secure\nCrypto Vault', 
                        style: TextStyle(
                          fontSize: 10, 
                          fontWeight: FontWeight.bold, 
                          color: Color(0xFFe4efe6), 
                          height: 1.1
                        ),
                        textAlign: TextAlign.center,
                      ),
                    ],
                  ),
                ),
              ),
              // 4. SECURE VAULT FILES (Com ícone de pastas em azul e largura 82)
                InkWell(
                  onTap: () {
                    Navigator.of(context).push(
                      MaterialPageRoute(builder: (context) => const VaultFilesGateScreen()),
                    );
                  },
                  borderRadius: BorderRadius.circular(12),
                  child: Container(
                    width: 82,
                  height: 74,
                    decoration: BoxDecoration(
                      borderRadius: BorderRadius.circular(12),
                      gradient: const LinearGradient(
                        begin: Alignment.topLeft,
                        end: Alignment.bottomRight,
                        colors: [
                          Color(0xFF1e4d2b),
                          Color(0xFF0a1a12),
                        ],
                      ),
                      border: Border.all(
                        color: Colors.lightBlueAccent.withValues(alpha: 0.35),
                        width: 1.2,
                      ),
                      boxShadow: [
                        BoxShadow(
                          color: Colors.lightBlueAccent.withValues(alpha: 0.2),
                          blurRadius: 15,
                          spreadRadius: 1,
                          offset: const Offset(0, 4),
                        ),
                      ],
                    ),
                    child: const Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Icon(Icons.folder_copy_rounded, color: Colors.lightBlueAccent, size: 28),
                        SizedBox(height: 2),
                        Text(
                          'Secure\nVault Files', 
                          style: TextStyle(
                            fontSize: 9.5, 
                            fontWeight: FontWeight.bold, 
                            color: Color(0xFFe4efe6), // Branco pérola
                            height: 1.1
                          ),
                          textAlign: TextAlign.center,
                        ),
                      ],
                    ),
                  ),
                ),
            ],
          ),
          const SizedBox(height: 25),

          Container(
  margin: const EdgeInsets.symmetric(horizontal: 15),
  width: double.infinity,
  padding: const EdgeInsets.all(16),
  decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(16),
            gradient: LinearGradient(
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
              colors: [
                Color(0xFF1e4d2b), // Tom claro do espelho
                Color(0xFF0a1a12), // Tom escuro/sombra
              ],
            ),
            border: Border.all(
              color: Colors.greenAccent.withValues(alpha: 0.35),
              width: 1.2,
            ),
            boxShadow: [
              BoxShadow(
                color: Colors.greenAccent.withValues(alpha: 0.2),
                blurRadius: 15,
                spreadRadius: 1,
                offset: const Offset(0, 4),
              ),
            ],
          ),
          child: Column(
          crossAxisAlignment: CrossAxisAlignment.center,
          children: [
           const Text(
      'ID de Privacidade',
      textAlign: TextAlign.center,
      style: TextStyle(fontSize: 13, fontWeight: FontWeight.bold, color: Colors.white70),
    ),
    const SizedBox(height: 6),
    SelectableText(
      privacyId,
      textAlign: TextAlign.center,
      style: const TextStyle(fontSize: 15, fontWeight: FontWeight.bold, color: Colors.white),
    ),
    const SizedBox(height: 12),
    const Divider(color: Colors.greenAccent, thickness: 0.5, height: 1),
    const SizedBox(height: 12),
    const Text(
      'Bio',
      textAlign: TextAlign.center,
      style: TextStyle(fontSize: 13, fontWeight: FontWeight.bold, color: Colors.white70),
    ),
    const SizedBox(height: 6),
    const Text(
      'Engineered with military-grade Zero-Knowledge encryption.\n'
      'All communications operate strictly Peer-to-Peer (P2P).\n'
      'Messages automatically self-destruct after 24 hours\n'
      'using secure anti-trace memory sanitization.\n'
      'Zero trace, zero logs, total privacy.',
      textAlign: TextAlign.center,
      style: TextStyle(fontSize: 12, color: Colors.white, height: 1.4),
    ),
          ],
  ),
),
        ],
      ),
    ));
  }

 Widget _buildActionButton(IconData icon, String label, VoidCallback onTap, {Color color = Colors.redAccent}) {
  return InkWell(
    onTap: onTap,
    borderRadius: BorderRadius.circular(12),
    child: Container(
      width: 82,
      padding: const EdgeInsets.symmetric(vertical: 10),
      decoration: BoxDecoration(
      borderRadius: BorderRadius.circular(12),
      gradient: const LinearGradient(
        begin: Alignment.topLeft,
        end: Alignment.bottomRight,
        colors: [
          Color(0xFF1e4d2b), // Tom claro do espelho
          Color(0xFF0a1a12), // Tom escuro/sombra
        ],
      ),
      border: Border.all(
        color: Colors.greenAccent.withValues(alpha: 0.35),
        width: 1.2,
      ),
      boxShadow: [
        BoxShadow(
          color: Colors.greenAccent.withValues(alpha: 0.2),
          blurRadius: 15,
          spreadRadius: 1,
          offset: const Offset(0, 4),
        ),
      ],
    ),
      child: Column(
        children: [
          Icon(icon, color: color, size: 26),
          const SizedBox(height: 6),
          Text(
            label, 
            style: const TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: Colors.white),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    ),
  );
}
}
void _showQrDialog(BuildContext context, String id, [dynamic local]) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: const Color(0xFF1A1A1A),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
          side: const BorderSide(color: Color(0xFF8B0000), width: 1.5),
        ),
        title: const Text(
          'Your QR Code',
          style: TextStyle(color: Colors.white),
        ),
        content: SizedBox(
          width: 220,
          height: 220,
          child: Center(
            child: Text(
              id,
              textAlign: TextAlign.center,
              style: const TextStyle(color: Colors.white70, fontSize: 13),
            ),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(local?['close'] ?? 'close', style: const TextStyle(color: Color(0xFF8B0000))),
          ),
        ],
      ),
    );
  }

// -
//---------------------------------------------------
// ACTIVE CALL SCREEN
// ----------------------------------------------------
class ActiveCallScreen extends StatefulWidget {
  final Map<String, String>? local;
  final String recipientName;
  final String targetId;
  final bool isIncoming;
  final dynamic channel;
  final dynamic incomingSdp;
  final bool acceptedViaCallKit;
  final bool isVideo;

  const ActiveCallScreen({
    super.key,
    required this.local,
    required this.recipientName,
    required this.targetId,
    this.isIncoming = false,
    this.channel,
    this.incomingSdp,
    this.acceptedViaCallKit = false,
    this.isVideo = false,
  });

  @override
  State<ActiveCallScreen> createState() => _ActiveCallScreenState();
}
class _ActiveCallScreenState extends State<ActiveCallScreen> {
  Timer? _callTimeoutTimer;
  Timer? _activeCallTimer;
  Timer? _ringingTimer; // Temporizador para o som do tuuu... tuuu
  int _secondsElapsed = 0;
  bool _callHandled = false;
  bool _isEnding = false;
  bool _isMuted = false;
  bool _isSpeakerOn = false;
  final AudioPlayer _audioPlayer = AudioPlayer();

  String _callStatusText = 'Connecting...';
  Color _callStatusColor = Colors.orangeAccent;

  RTCPeerConnection? _peerConnection;
  MediaStream? _localStream;
  StreamSubscription? _callSubscription;
  final List<RTCIceCandidate> _candidateQueue = [];
bool _isRemoteSet = false;
  final RTCVideoRenderer _localRenderer = RTCVideoRenderer();
  final RTCVideoRenderer _remoteRenderer = RTCVideoRenderer();
  bool _videoRenderersReady = false;
  bool _swapVideos = false; // toca na imagem pequena para trocar com o ecrã grande
  Offset? _pipOffset; // posição do quadradinho pequeno (arrastável), null = ainda não definida (usa a posição por omissão)
  Offset? _bubbleOffset; // posição da bolha minimizada (arrastável), null = ainda não definida
  @override
  void initState() {
    super.initState();
    PadlockNetwork.emChamada = true;
    WakelockPlus.enable();
    if (widget.isVideo) {
      Future.wait([_localRenderer.initialize(), _remoteRenderer.initialize()]).then((_) {
        if (mounted) setState(() => _videoRenderersReady = true);
      });
    }
    for (var candData in PadlockNetwork.earlyCandidates) {
      final candMap = candData['candidate'];
      if (candMap != null) {
        RTCIceCandidate candidate = RTCIceCandidate(
          candMap['candidate']?.toString() ?? '',
          candMap['sdpMid']?.toString(),
          candMap['sdpMLineIndex'] != null ? int.tryParse(candMap['sdpMLineIndex'].toString()) ?? 0 : 0,
        );
        _candidateQueue.add(candidate);
      }
    }
    PadlockNetwork.earlyCandidates.clear();
    // 1. ESCUTA ATIVA: Interceta a Resposta e as Chaves da outra pessoa em tempo real
    _callSubscription = PadlockNetwork.messageHub.stream.listen((data) async {
      try {
        final decoded = jsonDecode(data);
        if (decoded['action'] == 'call_answer' && !widget.isIncoming) {
          setState(() {
            _callStatusText = 'Exchanging Encryption Keys...';
            _callStatusColor = Colors.lightBlueAccent;
          });
          _audioPlayer.play(AssetSource('sounds/morse.mp3')).catchError((e) => print('Erro audio: $e'));
          _audioPlayer.setVolume(0.3);
          RTCSessionDescription remoteDesc = RTCSessionDescription(
            decoded['sdp']['sdp'],
            decoded['sdp']['type'],
          );
          await _peerConnection?.setRemoteDescription(remoteDesc);
          _isRemoteSet = true;
          for (var candidate in _candidateQueue) {
            await _peerConnection?.addCandidate(candidate);
          }
          _candidateQueue.clear();
          _isRemoteSet = true;
        } else if (decoded['action'] == 'call_candidate') {
          final candMap = decoded['candidate'];
          if (candMap != null) {
            RTCIceCandidate candidate = RTCIceCandidate(
              candMap['candidate']?.toString() ?? '',
              candMap['sdpMid']?.toString(),
              candMap['sdpMLineIndex'] != null ? int.tryParse(candMap['sdpMLineIndex'].toString()) ?? 0 : 0,
            );
            if (_peerConnection != null && _isRemoteSet) {
              _peerConnection!.addCandidate(candidate);
            } else {
              _candidateQueue.add(candidate);
            }
          }
        }
        // Bug encontrado: faltava fechar o bloco de 'call_candidate' acima -
        // isso deixava 'call_ringing' preso como o "else" do "if (candMap !=
        // null)", nunca alcançável por uma mensagem real de call_ringing (só
        // seria possível a ação ser 'call_candidate' E 'call_ringing' ao
        // mesmo tempo). Resultado: o Morse nunca parava e o estado nunca
        // mudava para "Ringing...", mesmo com o outro telemóvel a tocar.
        else if (decoded['action'] == 'call_ringing') {
          if (mounted) {
            setState(() {
              _callStatusText = 'Ringing...';
              _callStatusColor = Colors.greenAccent;
            });
            }
            _audioPlayer.stop();
            _audioPlayer.setVolume(0.3);
    _audioPlayer.setReleaseMode(ReleaseMode.loop);
    await _audioPlayer.setAudioContext(AudioContext(
  android: AudioContextAndroid(
    isSpeakerphoneOn: false,
    stayAwake: true,
    contentType: AndroidContentType.music,
    usageType: AndroidUsageType.voiceCommunicationSignalling,
    audioFocus: AndroidAudioFocus.gainTransient,
  ),
));
    _audioPlayer.play(AssetSource('sounds/ringing.mp3')).catchError((e) => print('Erro audio: $e'));
          }
        else if (decoded['action'] == 'call_end') {
          if (mounted) {
            _audioPlayer.stop();
            flutterLocalNotificationsPlugin.cancel(99);
            _audioPlayer.play(AssetSource('sounds/end_call.mp3'));
            Future.delayed(const Duration(milliseconds: 500), () {
            // A chamada já não é uma rota (ver PadlockCallOverlay) - fechar
            // é sempre isto, nunca matar a app nem mexer no Navigator.
            PadlockCallOverlay.hide();
          });
          }
        }
      } catch (e) {
        print('Erro a processar pacote P2P na chamada: $e');
      }
    });

    // 2. MODO DE ARRANQUE: Quem liga vs Quem recebe
   if (!widget.isIncoming) {
      setState(() {
        _callStatusText = 'Connecting Encrypted Call...';
        _callStatusColor = Colors.orangeAccent;
      });
      startSecureCall(widget.targetId);
      
      // O TEMPORIZADOR DE SAÍDA: Cancela a chamada se ninguém atender em 30 segundos
      _callTimeoutTimer?.cancel();
      _callTimeoutTimer = Timer(const Duration(seconds: 60), () {
        if (mounted && !_callHandled) {
          _callHandled = true;
          endCall(widget.targetId);
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('Contact Unavailable or Offline.', style: TextStyle(color: Colors.red))),
          );
        }
      });
      
    } else {
      setState(() {
        _callStatusText = 'Incoming Encrypted Call...';
        _callStatusColor = const Color(0xFF00FF66);
      });
      _startMissedCallTimer();
    Future.delayed(const Duration(milliseconds: 1500), () {
     final ringingSignal = {
  'action': 'call_ringing',
  'targetId': widget.targetId,
};
widget.channel?.sink.add(jsonEncode(ringingSignal));
});
// Aciona o toque para quem recebe a chamada (com o nome exato do teu ficheiro)
if (!widget.acceptedViaCallKit) {
  _audioPlayer.setReleaseMode(ReleaseMode.loop);
  _audioPlayer.setAudioContext(AudioContext(android: AudioContextAndroid(isSpeakerphoneOn: true, stayAwake: true, contentType: AndroidContentType.music, usageType: AndroidUsageType.notificationRingtone, audioFocus: AndroidAudioFocus.gainTransient)));
  _audioPlayer.setVolume(0.7);
  _audioPlayer.play(AssetSource('sounds/ringtone.mp3.mp3'));
}
      if (widget.acceptedViaCallKit) {
        _callHandled = true;
        _callTimeoutTimer?.cancel();
        acceptSecureCall();
      }
    }
  }

  @override
  void dispose() {
    _callSubscription?.cancel();
    PadlockNetwork.emChamada = false;
    WakelockPlus.disable();
    _callTimeoutTimer?.cancel();
    _activeCallTimer?.cancel();
    _ringingTimer?.cancel();
    _audioPlayer.dispose();
    _localStream?.dispose();
    _peerConnection?.dispose();
    _localRenderer.dispose();
    _remoteRenderer.dispose();
    super.dispose();
  }

  void _startMissedCallTimer() {
    _callTimeoutTimer?.cancel();
    _callTimeoutTimer = Timer(const Duration(seconds: 60), () {
      if (mounted && !_callHandled) {
        _callHandled = true;
        _logMissedCall();
        endCall(widget.targetId); // endCall já fecha a chamada (PadlockCallOverlay.hide())
      }
    });
  }

  void _startActiveTimer() {
    _callTimeoutTimer?.cancel(); // Cancela o timer de chamada perdida
    _activeCallTimer?.cancel();
    _activeCallTimer = Timer.periodic(const Duration(seconds: 1), (timer) {
      if (mounted) {
        setState(() {
          _secondsElapsed++;
          final minutes = (_secondsElapsed ~/ 60).toString().padLeft(2, '0');
          final seconds = (_secondsElapsed % 60).toString().padLeft(2, '0');
          _callStatusText = 'Connected ($minutes:$seconds)';
        });
      }
    });
  }

  void _logMissedCall() {
    try {
      final vault = Hive.box('padlock_vault');
      String? chatsJson = vault.get('chats');
      List<dynamic> allChats = chatsJson != null ? jsonDecode(chatsJson) : [];
      
      int chatIdx = allChats.indexWhere((c) => c['id'].toString() == widget.targetId.toString());
      final now = DateTime.now().millisecondsSinceEpoch;
      final timeStr = "${DateTime.now().hour.toString().padLeft(2, '0')}:${DateTime.now().minute.toString().padLeft(2, '0')}";
      final missedMsg = '📞 Missed Secure Call ($timeStr)';

      if (chatIdx != -1) {
        if (allChats[chatIdx]['messages'] == null) allChats[chatIdx]['messages'] = [];
        allChats[chatIdx]['messages'].add({'text': missedMsg, 'isMe': false, 'status': 'missed', 'timestamp': now});
        allChats[chatIdx]['msg'] = '📞 Missed Secure Call';
        allChats[chatIdx]['time'] = timeStr;
        allChats[chatIdx]['unread'] = (allChats[chatIdx]['unread'] ?? 0) + 1;
      }
      vault.put('chats', jsonEncode(allChats));
      flutterLocalNotificationsPlugin.show(DateTime.now().millisecond, 'Padlock - Missed Call', missedMsg, const NotificationDetails(android: AndroidNotificationDetails('padlock_msg_channel', 'Secure Messages', importance: Importance.max, priority: Priority.high, playSound: true)));
    } catch (e) {
      print('Erro ao registar chamada perdida: $e');
    }
  }

  void _setupPeerConnectionListeners() {
    _peerConnection?.onIceConnectionState = (state) {
      if (!mounted) return;
      setState(() {
        if (state == RTCIceConnectionState.RTCIceConnectionStateConnected || 
            state == RTCIceConnectionState.RTCIceConnectionStateCompleted) {
          _callStatusText = 'Connected and Encrypted';
          _callStatusColor = const Color(0xFF00FF66);
          _startActiveTimer();
          _audioPlayer.stop(); // Corta o Morse/Ringing imediatamente assim que atende!
          // A chamada atendeu! Agora sim, passa o som da voz para o ouvido
        if (_localStream != null && _localStream!.getAudioTracks().isNotEmpty) {
  _localStream!.getAudioTracks()[0].enableSpeakerphone(false);
}
        } else if (state == RTCIceConnectionState.RTCIceConnectionStateDisconnected) {
          // EFEITO TÚNEL: Net caiu. Não desliga a chamada, espera que recupere.
          _callStatusText = 'Reconnecting...';
          _callStatusColor = Colors.orangeAccent;
          _audioPlayer.play(AssetSource('sounds/morse.mp3')); // Toca Morse no túnel
          _peerConnection?.restartIce(); // Força a religação à nova rede (Wi-Fi -> 5G)
        } else if (state == RTCIceConnectionState.RTCIceConnectionStateFailed ||
                   state == RTCIceConnectionState.RTCIceConnectionStateClosed) {
          // Falha crítica irrecuperável ou chamada terminada
          _audioPlayer.stop();
          endCall(widget.targetId); // já chama PadlockCallOverlay.hide() e o som de fim de chamada
        }
      });
    };

    // Vídeo: o áudio já toca sozinho no motor nativo do WebRTC, mas para
    // MOSTRAR a imagem remota é preciso agarrar a faixa de vídeo aqui.
    _peerConnection?.onTrack = (RTCTrackEvent event) {
      if (event.track.kind == 'video' && event.streams.isNotEmpty) {
        _remoteRenderer.srcObject = event.streams[0];
      }
    };

    // Necessário para furar os firewalls (Sinalização P2P perfeita)
    _peerConnection?.onIceCandidate = (RTCIceCandidate candidate) {
      final candidateSignal = {
        'action': 'call_candidate',
        'targetId': widget.targetId,
        'candidate': candidate.toMap(),
      };
      widget.channel?.sink.add(jsonEncode(candidateSignal));
    };
  }

  // Pede a configuração TURN ao servidor em vez de a ter fixa no APK
  // (credenciais fixas no cliente eram extraíveis por descompilação).
  Future<List<Map<String, dynamic>>> _fetchIceServers() async {
    final fallback = <Map<String, dynamic>>[
      {'urls': 'stun:stun.l.google.com:19302'},
    ];
    if (widget.channel == null) return fallback;
    try {
      final completer = Completer<List<Map<String, dynamic>>>();
      late StreamSubscription sub;
      sub = PadlockNetwork.messageHub.stream.listen((raw) {
        try {
          final decoded = jsonDecode(raw);
          if (decoded['type'] == 'ice_servers' && !completer.isCompleted) {
            final servers = (decoded['iceServers'] as List)
                .map((e) => Map<String, dynamic>.from(e))
                .toList();
            completer.complete(servers);
          }
        } catch (_) {}
      });
      widget.channel?.sink.add(jsonEncode({'type': 'get_ice_servers'}));
      final result = await completer.future.timeout(
        const Duration(seconds: 4),
        onTimeout: () => fallback,
      );
      await sub.cancel();
      return result;
    } catch (e) {
      return fallback;
    }
  }

  Future<void> startSecureCall(String targetPrivacyId) async {
    var status = await Permission.microphone.request();
    if (status != PermissionStatus.granted) return;
    if (!mounted) return;
    setState(() {
      _callStatusText = 'Connecting Encrypted Call...';
      _callStatusColor = Colors.orangeAccent;
    });

    try {
      final Map<String, dynamic> configuration = {
        'iceServers': await _fetchIceServers(),
        'bundlePolicy': 'max-bundle',
        'rtcpMuxPolicy': 'require',
      };

      _peerConnection = await createPeerConnection(configuration);
      _setupPeerConnectionListeners();

      _localStream = await navigator.mediaDevices.getUserMedia({'audio': true, 'video': widget.isVideo});
      if (widget.isVideo) _localRenderer.srcObject = _localStream;

// Chamada de voz: som pelo auscultador. Chamada de vídeo: altifalante (faz
// sentido veres o ecrã ao mesmo tempo que ouves).
if (_localStream != null && _localStream!.getAudioTracks().isNotEmpty) {
  _localStream!.getAudioTracks()[0].enableSpeakerphone(widget.isVideo);
}

      for (var track in _localStream!.getTracks()) {
        _peerConnection!.addTrack(track, _localStream!);
      }

      RTCSessionDescription offer = await _peerConnection!.createOffer();
      await _peerConnection!.setLocalDescription(offer);

      final callSignal = {
          'action': 'call_offer',
          'type': 'offer',
          'senderId': Hive.box('padlock_vault').get('user_privacy_id'),
          'targetId': targetPrivacyId,
          'sdp': offer.toMap(),
          'isVideo': widget.isVideo,
          'timestamp': DateTime.now().millisecondsSinceEpoch,
        };
      widget.channel?.sink.add(jsonEncode(callSignal));
      _audioPlayer.setReleaseMode(ReleaseMode.loop);
      await _audioPlayer.setAudioContext(AudioContext(
  android: AudioContextAndroid(
   isSpeakerphoneOn: false,
    stayAwake: true,
    contentType: AndroidContentType.music,
    usageType: AndroidUsageType.voiceCommunicationSignalling,
    audioFocus: AndroidAudioFocus.gainTransient,
  ),
));
_audioPlayer.setVolume(0.3);
_audioPlayer.play(AssetSource('sounds/morse.mp3'));
    } catch (e) {
      print('Erro ao iniciar motor WebRTC P2P: $e');
    }
  }

  Future<void> acceptSecureCall() async {
    var status = await Permission.microphone.request();
    if (status != PermissionStatus.granted) return;

    setState(() {
      _callStatusText = 'Exchanging Encryption Keys...';
      _callStatusColor = Colors.lightBlueAccent;
    });

    try {
      final Map<String, dynamic> configuration = {
        'iceServers': await _fetchIceServers(),
        'bundlePolicy': 'max-bundle',
        'rtcpMuxPolicy': 'require',
      };

      _peerConnection = await createPeerConnection(configuration);
      _setupPeerConnectionListeners();
     

      _localStream = await navigator.mediaDevices.getUserMedia({'audio': true, 'video': widget.isVideo});
      if (widget.isVideo) {
        _localRenderer.srcObject = _localStream;
        if (_localStream!.getAudioTracks().isNotEmpty) {
          _localStream!.getAudioTracks()[0].enableSpeakerphone(true);
        }
      }
      for (var track in _localStream!.getTracks()) {
        _peerConnection!.addTrack(track, _localStream!);
      }

      if (widget.incomingSdp != null) {
        _audioPlayer.stop();
        final sdpMap = (widget.incomingSdp is String) ? jsonDecode(widget.incomingSdp) : widget.incomingSdp;
        RTCSessionDescription remoteDesc = RTCSessionDescription(
          sdpMap['sdp'],
          sdpMap['type'],
        );
        await _peerConnection!.setRemoteDescription(remoteDesc);
_isRemoteSet = true;
        for (var candidate in _candidateQueue) {
          await _peerConnection!.addCandidate(candidate);
        }
        _candidateQueue.clear();
      }

      RTCSessionDescription answer = await _peerConnection!.createAnswer();
      await _peerConnection!.setLocalDescription(answer);

      final answerSignal = {
  'action': 'call_answer',
  'type': 'answer',
  'senderId': Hive.box('padlock_vault').get('user_privacy_id'),
  'targetId': widget.targetId,
  'sdp': answer.toMap(),
  'timestamp': DateTime.now().millisecondsSinceEpoch,
};
      widget.channel?.sink.add(jsonEncode(answerSignal));
      _audioPlayer.stop();
flutterLocalNotificationsPlugin.cancel(99);
    } catch (e) {
      print('Erro ao aceitar chamada P2P: $e');
    }
  }

  Future<void> endCall(String targetPrivacyId) async {
    PadlockNetwork.emChamada = false;
    if (_isEnding) return;
    _isEnding = true;
    final endSignal = {
      'action': 'call_end',
      'targetId': targetPrivacyId,
    };
    widget.channel?.sink.add(jsonEncode(endSignal));
    try {
      _peerConnection?.close();
      _peerConnection?.dispose();
      _peerConnection = null;
    } catch (e) {}

    try {
      if (_localStream != null) {
        for (var track in _localStream!.getTracks()) track.stop();
        if (_localStream!.getAudioTracks().isNotEmpty) _localStream!.getAudioTracks()[0].enableSpeakerphone(true);
        _localStream!.dispose();
        _localStream = null;
      }
    } catch (e) {}

    _audioPlayer.stop();
    flutterLocalNotificationsPlugin.cancel(99);
    await FlutterCallkitIncoming.endAllCalls();
    await _audioPlayer.play(AssetSource('sounds/end_call.mp3'));
    await Future.delayed(const Duration(milliseconds: 500));
    
    PadlockNetwork.pendingCallData = null;

    // A chamada nunca é a única rota (ver PadlockCallOverlay) - o ecrã
    // principal está sempre por baixo, por isso nunca é preciso matar a
    // app aqui, mesmo tendo sido aceite via CallKit com a app fechada.
    PadlockCallOverlay.hide();
  }
  void _toggleMute() {
    if (_localStream != null) {
      setState(() {
        _isMuted = !_isMuted;
        _localStream!.getAudioTracks()[0].enabled = !_isMuted;
      });
    }
  }

  void _toggleSpeaker() {
    if (_localStream != null) {
      setState(() {
        _isSpeakerOn = !_isSpeakerOn;
        _localStream!.getAudioTracks()[0].enableSpeakerphone(_isSpeakerOn);
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    // A chamada agora vive numa camada persistente (Overlay), não numa rota -
    // por isso decide aqui, sozinha, se mostra o ecrã inteiro ou só a bolha
    // pequena minimizada, em vez de depender do Navigator para isso.
    return ValueListenableBuilder<bool>(
      valueListenable: PadlockCallOverlay.minimized,
      builder: (context, isMinimized, child) {
        return isMinimized ? _buildMinimizedBubble(context) : _buildFullScreenCall(context);
      },
    );
  }

  // Bolha pequena e arrastável, visível por cima de qualquer ecrã da app
  // (chat, contactos, Crypto Vault, Vault Files, ...) enquanto a chamada
  // continua ligada por baixo. Tocar reabre o ecrã inteiro; a chamada só
  // termina de facto ao carregar no botão vermelho de desligar - nunca
  // simplesmente por navegar para outro lado.
  Widget _buildMinimizedBubble(BuildContext context) {
    final screenSize = MediaQuery.of(context).size;
    const double bubbleWidth = 160, bubbleHeight = 56;
    final offset = _bubbleOffset ?? Offset(16, screenSize.height - 220);
    return Stack(
      children: [
        Positioned(
          left: offset.dx,
          top: offset.dy,
          child: GestureDetector(
            onTap: () => PadlockCallOverlay.minimized.value = false,
            onPanUpdate: (details) {
              setState(() {
                final current = _bubbleOffset ?? offset;
                final newX = (current.dx + details.delta.dx).clamp(0.0, screenSize.width - bubbleWidth);
                final newY = (current.dy + details.delta.dy).clamp(0.0, screenSize.height - bubbleHeight);
                _bubbleOffset = Offset(newX, newY);
              });
            },
            child: Container(
              width: bubbleWidth,
              height: bubbleHeight,
              padding: const EdgeInsets.symmetric(horizontal: 14),
              decoration: BoxDecoration(
                color: const Color(0xFF101411).withValues(alpha: 0.95),
                borderRadius: BorderRadius.circular(30),
                border: Border.all(color: _callStatusColor.withValues(alpha: 0.7), width: 1.5),
                boxShadow: [BoxShadow(color: Colors.black.withValues(alpha: 0.5), blurRadius: 10, spreadRadius: 1)],
              ),
              child: Row(
                children: [
                  Icon(widget.isVideo ? Icons.videocam : Icons.call, color: _callStatusColor, size: 18),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(widget.recipientName, overflow: TextOverflow.ellipsis, style: const TextStyle(color: Colors.white, fontSize: 12, fontWeight: FontWeight.bold)),
                        Text(_callStatusText, overflow: TextOverflow.ellipsis, style: TextStyle(color: _callStatusColor, fontSize: 10)),
                      ],
                    ),
                  ),
                  GestureDetector(
                    onTap: () {
                      _callHandled = true;
                      _callTimeoutTimer?.cancel();
                      endCall(widget.targetId);
                    },
                    child: const Icon(Icons.call_end, color: Color(0xFFFF1515), size: 22),
                  ),
                ],
              ),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildFullScreenCall(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      body: Stack(
        children: [
         Positioned.fill(
            child: Container(
              decoration: const BoxDecoration(
                image: DecorationImage(
                  image: AssetImage('assets/fundo matrix.png'),
                  fit: BoxFit.cover,
                  colorFilter: ColorFilter.mode(Colors.black87, BlendMode.darken),
                ),
              ),
            ),
          ), // 1. Fundo do Matrix em código  ),
          // Botão de minimizar - sempre visível (voz ou vídeo), no topo à
          // esquerda para não conflitar com o quadradinho da câmara (topo à
          // direita) nem com a barra de nome/estado do vídeo (centro).
          SafeArea(
            child: Padding(
              padding: const EdgeInsets.only(left: 12, top: 4),
              child: GestureDetector(
                onTap: () => PadlockCallOverlay.minimized.value = true,
                child: Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(shape: BoxShape.circle, color: Colors.black.withValues(alpha: 0.4)),
                  child: const Icon(Icons.keyboard_arrow_down, color: Colors.white, size: 22),
                ),
              ),
            ),
          ),
          // Camada escura mais transparente para o verde do Matrix brilhar bem
          if (widget.isVideo && _videoRenderersReady)
            Positioned.fill(
              child: RTCVideoView(
                _swapVideos ? _localRenderer : _remoteRenderer,
                mirror: _swapVideos,
                objectFit: RTCVideoViewObjectFit.RTCVideoViewObjectFitCover,
              ),
            ),
          if (widget.isVideo && _videoRenderersReady)
            Builder(builder: (context) {
              const double pipWidth = 100, pipHeight = 140;
              final screenSize = MediaQuery.of(context).size;
              // Posição por omissão: um pouco mais abaixo do que antes, para
              // nunca começar em cima da barra do cadeado/nome no topo.
              final offset = _pipOffset ?? Offset(screenSize.width - pipWidth - 16, 110);
              return Positioned(
                left: offset.dx,
                top: offset.dy,
                child: GestureDetector(
                  // Toca para trocar com o ecrã grande, ou arrasta para mover
                  // o quadradinho para onde quiseres - tal como noutras apps
                  // de videochamada.
                  onTap: () => setState(() => _swapVideos = !_swapVideos),
                  onPanUpdate: (details) {
                    setState(() {
                      final current = _pipOffset ?? offset;
                      final newX = (current.dx + details.delta.dx).clamp(0.0, screenSize.width - pipWidth);
                      final newY = (current.dy + details.delta.dy).clamp(0.0, screenSize.height - pipHeight);
                      _pipOffset = Offset(newX, newY);
                    });
                  },
                  child: Container(
                    width: pipWidth,
                    height: pipHeight,
                    clipBehavior: Clip.antiAlias,
                    decoration: BoxDecoration(
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(color: Colors.greenAccent.withValues(alpha: 0.6), width: 1.5),
                    ),
                    child: RTCVideoView(
                      _swapVideos ? _remoteRenderer : _localRenderer,
                      mirror: !_swapVideos,
                      objectFit: RTCVideoViewObjectFit.RTCVideoViewObjectFitCover,
                    ),
                  ),
                ),
              );
            }),
          if (widget.isVideo)
            // Nome/estado pequeninos no topo, em vez do cadeado grande a
            // meio do ecrã - só para identificar com quem estás a falar,
            // sem tapar a imagem.
            SafeArea(
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                child: Row(
                  children: [
                    Container(
                      padding: const EdgeInsets.all(6),
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        color: Colors.black.withValues(alpha: 0.4),
                      ),
                      child: const Icon(Icons.lock, color: Colors.greenAccent, size: 14),
                    ),
                    const SizedBox(width: 8),
                    Flexible(
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                        decoration: BoxDecoration(
                          color: Colors.black.withValues(alpha: 0.4),
                          borderRadius: BorderRadius.circular(20),
                        ),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Text(
                              widget.recipientName,
                              overflow: TextOverflow.ellipsis,
                              style: const TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.bold, fontFamily: 'monospace'),
                            ),
                            Text(
                              _callStatusText,
                              overflow: TextOverflow.ellipsis,
                              style: TextStyle(color: _callStatusColor, fontSize: 10, fontWeight: FontWeight.bold),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ),

          // 2. Elementos Visuais do Ecrã de Chamada
          SafeArea(
            child: Align(
              // Em vídeo, o cadeado e os botões ficam em baixo, pequenos, para
              // não tapar a imagem da outra pessoa a meio do ecrã.
              alignment: widget.isVideo ? const Alignment(0, 0.88) : Alignment.center,
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 20.0),
                child: Transform.scale(
                  scale: widget.isVideo ? 0.62 : 1.0,
                  alignment: Alignment.bottomCenter,
                  child: Column(
                  // Sem isto, a Column ocupava sempre o ecrã todo (tamanho
                  // por omissão), o que anulava o Align lá em cima - por
                  // isso os botões ficavam sempre a meio do ecrã em vez de
                  // encostados ao fundo nas chamadas de vídeo.
                  mainAxisSize: widget.isVideo ? MainAxisSize.min : MainAxisSize.max,
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    // Cadeado com duplo anel néon - só nas chamadas de voz. Em
                    // vídeo isto tapava a imagem da outra pessoa; o nome/estado
                    // aparece à parte, pequenino, no topo (ver mais abaixo).
                    if (!widget.isVideo)
                    Stack(
                      alignment: Alignment.center,
                      children: [
                        Container(
                          width: 104,
                          height: 104,
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            color: const Color(0xFF101411).withValues(alpha: 0.9),
                            border: Border.all(
                              color: _callStatusColor.withValues(alpha: 0.35),
                              width: 6,
                            ),
                            boxShadow: [
                              BoxShadow(
                                color: _callStatusColor.withValues(alpha: 0.3),
                                blurRadius: 22,
                                spreadRadius: 2,
                              ),
                            ],
                          ),
                        ),
                        Container(
                          width: 76,
                          height: 76,
                          decoration: BoxDecoration(
          shape: BoxShape.circle,
          gradient: const LinearGradient(
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
            colors: [
              Color(0xFF1e4d2b),
              Color(0xFF0a1a12),
            ],
          ),
          border: Border.all(
          color: Colors.greenAccent.withValues(alpha: 0.7),
          width: 1.5,
        ),
        boxShadow: [
          BoxShadow(
            color: Colors.greenAccent.withValues(alpha: 0.3),
            blurRadius: 15,
            spreadRadius: 1,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: ClipOval(
        child: Image.asset(
          'assets/padlock-image.app.png',
          width: 40,
          height: 40,
          fit: BoxFit.cover,
        ),
      ),
                        ),
                      ],
                    ),
                    if (!widget.isVideo) ...[
                    const SizedBox(height: 30),

                    // ID / Nome do Contacto
                    Text(
                      widget.recipientName,
                      textAlign: TextAlign.center,
                      style: const TextStyle(
                        fontSize: 18,
                        fontWeight: FontWeight.bold,
                        fontFamily: 'monospace',
                        color: Colors.white,
                        letterSpacing: 1.2,
                      ),
                    ),
                    const SizedBox(height: 12),

                    // Estado da Chamada e Temporizador
                    Text(
                      _callStatusText,
                      textAlign: TextAlign.center,
                      style: TextStyle(
                        fontSize: 13,
                        color: _callStatusColor,
                        fontWeight: FontWeight.bold,
                        letterSpacing: 0.5,
                      ),
                    ),
                    ],
                    SizedBox(height: widget.isVideo ? 10 : 55),

                    // Botões dinâmicos (Recebidas vs Feitas/Ativas)
                    widget.isIncoming && !_callHandled
                        ? Row(
                            mainAxisAlignment: MainAxisAlignment.center,
                            children: [
                              _buildCallButton(
                                icon: Icons.call_end,
                                color: const Color(0xFFFF1515),
                                onPress: () {
                                  _callHandled = true;
                                  _callTimeoutTimer?.cancel();
                                  endCall(widget.targetId); // já fecha a chamada (PadlockCallOverlay.hide())
                                },
                              ),
                              const SizedBox(width: 40),
                              _buildCallButton(
                                icon: Icons.call,
                                color: const Color(0xFF00FF66),
                                onPress: () {
                                  _callHandled = true;
                                  _callTimeoutTimer?.cancel();
                                  acceptSecureCall();
                                },
                              ),
                            ],
                          )
                        : Row(
                            mainAxisAlignment: MainAxisAlignment.center,
                            children: [
                              // Botão MUTE (Microfone)
                      GestureDetector(
                        onTap: _toggleMute,
                        child: Container(
                          padding: const EdgeInsets.all(18),
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            color: _isMuted ? Colors.redAccent.withValues(alpha: 0.2) : Colors.white.withValues(alpha: 0.1),
                            border: Border.all(
                              color: _isMuted ? Colors.redAccent : Colors.transparent,
                              width: 2,
                            ),
                          ),
                          child: Icon(
                            _isMuted ? Icons.mic_off : Icons.mic, 
                            color: _isMuted ? Colors.redAccent : Colors.white,
                            size: 32,
                          ),
                        ),
                      ),
                      
                      const SizedBox(width: 25),
                      
                      // Botão Desligar (Vermelho Fixo)
                      GestureDetector(
                        onTap: () => endCall(widget.targetId),
                        child: Container(
                          padding: const EdgeInsets.all(24),
                          decoration: const BoxDecoration(
                            shape: BoxShape.circle,
                            color: Colors.redAccent,
                            boxShadow: [
                              BoxShadow(color: Colors.redAccent, blurRadius: 15, spreadRadius: 2),
                            ],
                          ),
                          child: const Icon(Icons.call_end, color: Colors.white, size: 36),
                        ),
                      ),
                      
                      const SizedBox(width: 25),
                      
                      // Botão Altifalante (Coluna Mãos-Livres)
                      GestureDetector(
                        onTap: _toggleSpeaker,
                        child: Container(
                          padding: const EdgeInsets.all(18),
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            color: _isSpeakerOn ? Colors.white : Colors.white.withValues(alpha: 0.1),
                          ),
                          child: Icon(
                            _isSpeakerOn ? Icons.volume_up : Icons.volume_down,
                            color: _isSpeakerOn ? Colors.black : Colors.white,
                            size: 32,
                          ),
                        ),
                      ),
                      if (widget.isVideo) ...[
                        const SizedBox(width: 25),
                        // Botão Virar Câmara (frente/trás)
                        GestureDetector(
                          onTap: () {
                            final videoTracks = _localStream?.getVideoTracks();
                            if (videoTracks != null && videoTracks.isNotEmpty) {
                              Helper.switchCamera(videoTracks[0]);
                            }
                          },
                          child: Container(
                            padding: const EdgeInsets.all(18),
                            decoration: BoxDecoration(
                              shape: BoxShape.circle,
                              color: Colors.white.withValues(alpha: 0.1),
                            ),
                            child: const Icon(Icons.cameraswitch, color: Colors.white, size: 32),
                          ),
                        ),
                      ],
                            ],
                          ),
                  ],
                ),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildCallButton({required IconData icon, required Color color, required VoidCallback onPress}) {
    return InkWell(
      onTap: onPress,
      borderRadius: BorderRadius.circular(30),
      child: Container(
        width: 55,
        height: 55,
        decoration: BoxDecoration(shape: BoxShape.circle, color: color),
        child: Icon(icon, color: Colors.white),
      ),
    );
  }
}

// ----------------------------------------------------
// SIMULADOR DE CODIGO QR DE PRIVACIDADE
// ----------------------------------------------------
class QrSimulatorPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = Colors.black
      ..style = PaintingStyle.fill;

    canvas.drawRect(const Rect.fromLTWH(0, 0, 45, 45), paint);
    canvas.drawRect(Rect.fromLTWH(size.width - 45, 0, 45, 45), paint);
    canvas.drawRect(Rect.fromLTWH(0, size.height - 45, 45, 45), paint);

    paint.color = Colors.white;
    canvas.drawRect(const Rect.fromLTWH(10, 10, 25, 25), paint);
    canvas.drawRect(Rect.fromLTWH(size.width - 35, 10, 25, 25), paint);
    canvas.drawRect(Rect.fromLTWH(10, size.height - 35, 25, 25), paint);

    paint.color = Colors.black;
    canvas.drawRect(const Rect.fromLTWH(15, 15, 15, 15), paint);
    canvas.drawRect(Rect.fromLTWH(size.width - 30, 15, 15, 15), paint);
    canvas.drawRect(Rect.fromLTWH(15, size.height - 30, 15, 15), paint);

    final random = Random(42);
    paint.color = Colors.black;
    for (double y = 50; y < size.height - 50; y += 10) {
      for (double x = 0; x < size.width; x += 10) {
        if (random.nextBool()) {
          canvas.drawRect(Rect.fromLTWH(x, y, 7, 7), paint);
        }
      }
    }
    for (double y = 0; y < 50; y += 10) {
      for (double x = 50; x < size.width - 50; x += 10) {
        if (random.nextBool()) {
          canvas.drawRect(Rect.fromLTWH(x, y, 7, 7), paint);
        }
      }
    }
    for (double y = size.height - 50; y < size.height; y += 10) {
      for (double x = 50; x < size.width; x += 10) {
        if (random.nextBool()) {
          canvas.drawRect(Rect.fromLTWH(x, y, 7, 7), paint);
        }
      }
    }
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}

class SetupScreen extends StatefulWidget {
  const SetupScreen({super.key});

  @override
  State<SetupScreen> createState() => _SetupScreenState();
}

// Força da frase de encriptação: agora É a única coisa entre um atacante e os
// dados (a chave do cofre deriva dela via Argon2id), por isso vale a pena
// travar frases triviais em vez de só medir o comprimento.
int _passphraseCategories(String s) {
  int c = 0;
  if (RegExp(r'[a-z]').hasMatch(s)) c++;
  if (RegExp(r'[A-Z]').hasMatch(s)) c++;
  if (RegExp(r'[0-9]').hasMatch(s)) c++;
  if (RegExp(r'[^a-zA-Z0-9]').hasMatch(s)) c++;
  return c;
}

bool _isTrivialPassphrase(String s) {
  if (s.isEmpty) return true;
  if (RegExp(r'^(.)\1*$').hasMatch(s)) return true; // ex: "aaaaaaaaaa"
  const commonWeak = [
    'password', 'password1', '12345678', '123456789', '1234567890',
    'qwertyui', 'qwertyuiop', 'letmein11', 'abcdefgh', 'abcd1234',
    '11111111', '00000000', 'iloveyou1', 'admin1234', 'padlock123',
  ];
  if (commonWeak.contains(s.toLowerCase())) return true;
  // Sequência simples crescente/decrescente (ex: "12345678", "abcdefgh")
  bool seqAsc = true, seqDesc = true;
  for (int i = 1; i < s.length; i++) {
    if (s.codeUnitAt(i) != s.codeUnitAt(i - 1) + 1) seqAsc = false;
    if (s.codeUnitAt(i) != s.codeUnitAt(i - 1) - 1) seqDesc = false;
  }
  if (s.length >= 6 && (seqAsc || seqDesc)) return true;
  return false;
}

// 0 = demasiado fraca (bloqueia), 1 = fraca, 2 = média, 3 = forte, 4 = muito forte
int _passphraseScore(String s) {
  if (s.length < 10 || _isTrivialPassphrase(s)) return 0;
  final categories = _passphraseCategories(s);
  int score = 1;
  if (s.length >= 12) score++;
  if (s.length >= 16) score++;
  if (categories >= 3) score++;
  return score.clamp(0, 4);
}

class _SetupScreenState extends State<SetupScreen> {
  final TextEditingController _keyController = TextEditingController();
  bool _obscureText = true;
  bool _isProcessing = false;
  int _strengthScore = 0;

  @override
  void initState() {
    super.initState();
    _keyController.addListener(() {
      setState(() => _strengthScore = _passphraseScore(_keyController.text.trim()));
    });
  }

  Future<void> _register() async {
    final key = _keyController.text.trim();
    if (_passphraseScore(key) < 1) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Decryption Key is too weak: use at least 10 characters and avoid repeated or sequential patterns.')),
      );
      return;
    }
    setState(() => _isProcessing = true);
    try {
      // Deriva a chave do cofre a partir da frase escolhida (Argon2id) - a frase
      // em si nunca é guardada, só um sal aleatório para repetir a derivação.
      final salt = await PadlockVaultKey.createSalt();
      final derivedKey = await PadlockVaultKey.deriveKey(key, salt);
      // Guarda o hash da chave ANTES de tocar no Hive - é isto que o ecrã de
      // login usa para validar a frase sem nunca abrir o cofre com a chave
      // errada (ver explicação completa em PadlockVaultKey.storeKeyHash).
      await PadlockVaultKey.storeKeyHash('padlock_vault_keyhash', derivedKey);
      final newVault = await Hive.openBox('padlock_vault', encryptionCipher: HiveAesCipher(derivedKey));
      // Valor de controlo: segunda camada de validação, para o caso raro de
      // o cofre ficar corrompido por outra razão.
      await newVault.put('_vault_canary', 'padlock_ok');

      if (PadlockNetwork.pendingFcmToken != null) {
        await Hive.box('padlock_vault').put('my_fcm_token', PadlockNetwork.pendingFcmToken);
      }
      // Fecha o cofre outra vez e manda para o ecrã de login normal, em vez
      // de entrar logo - obriga a confirmar a frase escrevendo-a de novo
      // (tal como pediste, e como era antes), e serve também de teste real
      // ao próprio caminho de login logo no primeiro uso.
      await Hive.box('padlock_vault').close();

      if (mounted) {
        Navigator.of(context).pushReplacement(
          MaterialPageRoute(builder: (context) => const LoginScreen()),
        );
      }
    } catch (e) {
      await PadlockVaultKey.wipe();
      await PadlockVaultKey.wipeKeyHash('padlock_vault_keyhash');
      if (Hive.isBoxOpen('padlock_vault')) {
        try { await Hive.box('padlock_vault').close(); } catch (_) {}
      }
      if (mounted) {
        setState(() => _isProcessing = false);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Vault initialization failed: $e')),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.transparent,
body: Container(
  decoration: const BoxDecoration(
    image: DecorationImage(
      image: AssetImage('assets/fundo matrix.png'),
      fit: BoxFit.cover,
      colorFilter: ColorFilter.mode(Colors.black87, BlendMode.darken),
    ),
  ),
  child: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(28.0),
          child: Column(
            children: [
              Container(
  width: 110,
  height: 110,
  decoration: BoxDecoration(
    shape: BoxShape.circle,
    gradient: const LinearGradient(
      begin: Alignment.topLeft,
      end: Alignment.bottomRight,
      colors: [
        Color(0xFF1e4d2b),
        Color(0xFF0a1a12),
      ],
    ),
    border: Border.all(
      color: Colors.greenAccent.withValues(alpha: 0.5),
      width: 1.5,
    ),
    boxShadow: [
      BoxShadow(
        color: Colors.greenAccent.withValues(alpha: 0.3),
        blurRadius: 20,
        spreadRadius: 2,
        offset: const Offset(0, 4),
      ),
    ],
  ),
  child: ClipOval(
    child: Image.asset(
      'assets/padlock-image.app.png',
      fit: BoxFit.cover,
    ),
  ),
),
              const SizedBox(height: 20),
              const Text(
                'CREATE YOUR ENCRYPTED VAULT',
                textAlign: TextAlign.center,
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 18,
                  fontWeight: FontWeight.bold,
                  letterSpacing: 1.2,
                ),
              ),
              const SizedBox(height: 12),
              const Text(
                'Set your master key to generate\nP2P cryptographic identity',
                textAlign: TextAlign.center,
                style: TextStyle(color: Colors.grey, fontSize: 11, height: 1.3),
              ),
              const SizedBox(height: 32),
              TextField(
                controller: _keyController,
                obscureText: _obscureText,
                style: const TextStyle(color: Colors.white),
                decoration: InputDecoration(
                  labelText: 'Set Decryption Key',
                  labelStyle: const TextStyle(color: Colors.grey),
                  enabledBorder: OutlineInputBorder(
                    borderSide: const BorderSide(color: Colors.grey),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  focusedBorder: OutlineInputBorder(
                    borderSide: const BorderSide(color: Colors.greenAccent),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  prefixIcon: const Icon(Icons.key, color: Colors.greenAccent),
                  suffixIcon: IconButton(
  icon: Icon(
    _obscureText ? Icons.visibility_off : Icons.visibility,
    color: Colors.grey,
  ),
  onPressed: () {
    setState(() {
      _obscureText = !_obscureText;
    });
  },
),
                ),
              ),
              if (_keyController.text.isNotEmpty) ...[
                const SizedBox(height: 10),
                Builder(builder: (context) {
                  const labels = ['Too weak', 'Weak', 'Medium', 'Strong', 'Very strong'];
                  const colors = [Colors.redAccent, Colors.orangeAccent, Colors.amber, Colors.lightGreen, Colors.greenAccent];
                  final score = _strengthScore;
                  return Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      ClipRRect(
                        borderRadius: BorderRadius.circular(4),
                        child: LinearProgressIndicator(
                          value: (score + 1) / 5,
                          minHeight: 5,
                          backgroundColor: Colors.white12,
                          valueColor: AlwaysStoppedAnimation<Color>(colors[score]),
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(labels[score], style: TextStyle(color: colors[score], fontSize: 11)),
                    ],
                  );
                }),
              ],
              const SizedBox(height: 24),
              SizedBox(
                width: double.infinity,
                height: 50,
                child: ElevatedButton(
                  style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.greenAccent,
                    foregroundColor: Colors.black,
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(8),
                    ),
                  ),
                  onPressed: _isProcessing ? null : _register,
                  child: _isProcessing
                      ? const SizedBox(
                          width: 22,
                          height: 22,
                          child: CircularProgressIndicator(strokeWidth: 2.5, color: Colors.black),
                        )
                      : const Text(
                          'INITIALIZE VAULT',
                          style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
                        ),
                ),
              ),
              const SizedBox(height: 36),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 10.0),
                child: Text(
                  'Engineered with military-grade Zero-Knowledge encryption.\n'
                  'All communications operate strictly Peer-to-Peer (P2P).\n'
                  'Messages automatically self-destruct after 24 hours\n'
                  'using secure anti-trace memory sanitization.\n'
                  'Zero trace, zero logs, total privacy.',
                  textAlign: TextAlign.center,
                  style: TextStyle(color: Colors.grey.shade600, fontSize: 10, height: 1.4),
                ),
              ),
            ],
          ),
        ),
      ),
    ));
  }
}

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final TextEditingController _keyController = TextEditingController();
  bool _obscureText = true;
  bool _isProcessing = false;

  Future<void> _login() async {
    final inputKey = _keyController.text.trim();
    if (inputKey.isEmpty) return;

    setState(() => _isProcessing = true);

    final salt = await PadlockVaultKey.getSalt();
    if (salt == null) {
      // Não devia acontecer (isFirstTime trataria este caso), mas por segurança
      // não avança sem sal - senão a derivação seria sempre com sal vazio.
      if (mounted) {
        setState(() => _isProcessing = false);
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Vault not initialized on this device.')),
        );
      }
      return;
    }

    try {
      final derivedKey = await PadlockVaultKey.deriveKey(inputKey, salt);

      // NUNCA chamar Hive.openBox com uma chave ainda não confirmada. Duas
      // descobertas juntas explicam o bug relatado ("depois de errar uma
      // vez, mesmo a chave CERTA passa a ser recusada, só resolve
      // reinstalando"): 1) a cifra do Hive não é autenticada, decifrar com a
      // chave errada nem sempre dá erro, às vezes dá LIXO que parece válido;
      // 2) quando o Hive falha a meio de abrir uma caixa, pode ficar
      // registado internamente como "aberta" mesmo sem o estar de verdade -
      // e todas as tentativas seguintes (mesmo com a chave certa) recebiam
      // essa MESMA instância avariada em vez de abrirem de novo. A validação
      // aqui é feita à parte, num hash simples, ANTES de sequer tocar no
      // Hive - assim o Hive só é aberto quando já se sabe, com toda a
      // certeza, que a chave está certa.
      final validKey = await PadlockVaultKey.verifyKeyHash('padlock_vault_keyhash', derivedKey);
      if (!validKey) {
        throw Exception('Invalid Decryption Key.');
      }

      if (Hive.isBoxOpen('padlock_vault')) {
        try { await Hive.box('padlock_vault').close(); } catch (_) {}
      }
      final opened = await Hive.openBox('padlock_vault', encryptionCipher: HiveAesCipher(derivedKey));

      // Segunda camada, dentro do próprio cofre - deve confirmar sempre,
      // dado que a chave já foi validada acima. Se alguma vez não bater
      // certo, é sinal de o próprio ficheiro do cofre estar corrompido, não
      // de a frase estar errada.
      final canary = opened.get('_vault_canary');
      if (canary != 'padlock_ok') {
        throw Exception('Vault data is corrupted (key was correct, but the vault file itself is damaged).');
      }

      PadlockNetwork.isUnlocked = true;
      if (PadlockNetwork.pendingFcmToken != null) {
        await Hive.box('padlock_vault').put('my_fcm_token', PadlockNetwork.pendingFcmToken);
      }

      if (mounted) {
        final pendingCall = PadlockNetwork.pendingCallData;
        // Vai sempre para o ecrã principal primeiro - mesmo havendo uma
        // chamada à espera. Antes, a chamada substituía o ecrã de login
        // como única rota, sem nada por baixo para onde voltar; agora ela
        // é mostrada por cima (ver PadlockCallOverlay), com o ecrã
        // principal já pronto por baixo para quando ela for minimizada ou
        // terminar.
        Navigator.of(context).pushReplacement(
          MaterialPageRoute(builder: (context) => MainNavigationScreen(currentLanguage: 'EN', onLanguageChange: (lang) {})),
        );
        if (pendingCall != null) {
          // Havia uma chamada à espera (aceite via CallKit com a app morta).
          PadlockCallOverlay.show(ActiveCallScreen(
            local: t['EN']!,
            recipientName: pendingCall['targetId'],
            targetId: pendingCall['targetId'],
            isIncoming: true,
            channel: PadlockNetwork.channel,
            incomingSdp: pendingCall['sdp'],
            acceptedViaCallKit: true,
            isVideo: pendingCall['isVideo'] == true,
          ));
        }
      }
    } catch (e) {
      // Chave errada: Hive não conseguiu decifrar o cofre. Fecha qualquer
      // instância parcialmente aberta para não bloquear a próxima tentativa.
      if (Hive.isBoxOpen('padlock_vault')) {
        try { await Hive.box('padlock_vault').close(); } catch (_) {}
      }
      if (mounted) {
        setState(() => _isProcessing = false);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('$e'.replaceFirst('Exception: ', ''))),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
   return Scaffold(
        backgroundColor: Colors.transparent,
        body: Container(
          decoration: const BoxDecoration(
            image: DecorationImage(
              image: AssetImage('assets/fundo matrix.png'),
              fit: BoxFit.cover,
              colorFilter: ColorFilter.mode(Colors.black87, BlendMode.darken),
            ),
          ),
          child: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(28.0),
          child: Column(
            children: [
              Container(
            width: 110,
            height: 110,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              gradient: const LinearGradient(
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
                colors: [
                  Color(0xFF1e4d2b),
                  Color(0xFF0a1a12),
                ],
              ),
              border: Border.all(
                color: Colors.greenAccent.withValues(alpha: 0.5),
                width: 1.5,
              ),
              boxShadow: [
                BoxShadow(
                  color: Colors.greenAccent.withValues(alpha: 0.3),
                  blurRadius: 20,
                  spreadRadius: 2,
                  offset: const Offset(0, 4),
                ),
              ],
            ),
            child: ClipOval(
              child: Image.asset(
                'assets/padlock-image.app.png',
                fit: BoxFit.cover,
              ),
            ),
          ),
          const SizedBox(height: 20),
              
              // Título Principal
              const Text(
                'DECRYPT YOUR PADLOCK',
                textAlign: TextAlign.center,
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 18,
                  fontWeight: FontWeight.bold,
                  letterSpacing: 1.2,
                ),
              ),
              const SizedBox(height: 12),

              // Subtítulo (Opção 2 com quebra de linha para telemóvel)
              const Text(
                'ENGINEERED WITH MILITARY-GRADE\nZERO-KNOWLEDGE ENCRYPTION',
                textAlign: TextAlign.center,
                style: TextStyle(color: Colors.grey, fontSize: 11, height: 1.3, letterSpacing: 1.0),
              ),
              const SizedBox(height: 32),

              // Campo para introduzir a Chave
              TextField(
                controller: _keyController,
                obscureText: _obscureText,
                style: const TextStyle(color: Colors.white),
                decoration: InputDecoration(
                  labelText: 'Enter Decryption Key',
                  labelStyle: const TextStyle(color: Colors.grey),
                  enabledBorder: OutlineInputBorder(
                    borderSide: const BorderSide(color: Colors.grey),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  focusedBorder: OutlineInputBorder(
                    borderSide: const BorderSide(color: Colors.greenAccent),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  prefixIcon: const Icon(Icons.key, color: Colors.greenAccent),
                  suffixIcon: IconButton(
  icon: Icon(
    _obscureText ? Icons.visibility_off : Icons.visibility,
    color: Colors.grey,
  ),
  onPressed: () {
    setState(() {
      _obscureText = !_obscureText;
    });
  },
),
                ),
              ),
              const SizedBox(height: 24),

              // Botão de Acesso
              SizedBox(
                width: double.infinity,
                height: 50,
                child: ElevatedButton(
                  style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.greenAccent,
                    foregroundColor: Colors.black,
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(8),
                    ),
                  ),
                  onPressed: _isProcessing ? null : _login,
                  child: _isProcessing
                      ? const SizedBox(
                          width: 22,
                          height: 22,
                          child: CircularProgressIndicator(strokeWidth: 2.5, color: Colors.black),
                        )
                      : const Text(
                          'ACCESS VAULT',
                          style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
                        ),
                ),
              ),
              const SizedBox(height: 36),

              // Texto Informativo do Rodapé (Formatado para telemóvel)
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 10.0),
                child: Text(
                  'Engineered with military-grade Zero-Knowledge encryption.\n'
                  'All communications operate strictly Peer-to-Peer (P2P).\n'
                  'Messages automatically self-destruct after 24 hours\n'
                  'using secure anti-trace memory sanitization.\n'
                  'Zero trace, zero logs, total privacy.',
                  textAlign: TextAlign.center,
                  style: TextStyle(color: Colors.grey.shade600, fontSize: 10, height: 1.4),
                ),
              ),
            ],
          ),
        ),
        ),
      ),
    );
  }
}

// ----------------------------------------------------
// SECURE VAULT FILES - ecrã de entrada (código próprio, separado do da app)
// ----------------------------------------------------
class VaultFilesGateScreen extends StatefulWidget {
  const VaultFilesGateScreen({super.key});

  @override
  State<VaultFilesGateScreen> createState() => _VaultFilesGateScreenState();
}

class _VaultFilesGateScreenState extends State<VaultFilesGateScreen> {
  final TextEditingController _codeController = TextEditingController();
  bool _obscureText = true;
  bool _isProcessing = false;
  bool? _isFirstTime;

  @override
  void initState() {
    super.initState();
    VaultFilesKey.hasVault().then((has) {
      if (mounted) setState(() => _isFirstTime = !has);
    });
  }

  Future<void> _submit() async {
    final code = _codeController.text.trim();
    final firstTime = _isFirstTime == true;

    if (firstTime && _passphraseScore(code) < 1) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Code is too weak: use at least 10 characters and avoid repeated or sequential patterns.')),
      );
      return;
    }
    if (!firstTime && code.isEmpty) return;

    setState(() => _isProcessing = true);
    try {
      final salt = firstTime ? await VaultFilesKey.createSalt() : await VaultFilesKey.getSalt();
      if (salt == null) throw Exception('Vault Files not initialized on this device.');

      final derivedKey = await PadlockVaultKey.deriveKey(code, salt);

      // Nunca abrir o Hive com uma chave ainda não confirmada - mesma razão
      // do login principal: uma chave errada pode não dar erro nenhum (só
      // lixo que parece válido), e uma abertura falhada pode deixar a caixa
      // presa, recusando a chave certa nas tentativas seguintes.
      if (firstTime) {
        await PadlockVaultKey.storeKeyHash('padlock_vault_files_keyhash', derivedKey);
      } else {
        final validKey = await PadlockVaultKey.verifyKeyHash('padlock_vault_files_keyhash', derivedKey);
        if (!validKey) {
          throw Exception('Invalid Vault Files code.');
        }
      }

      if (Hive.isBoxOpen('padlock_vault_files')) {
        try { await Hive.box('padlock_vault_files').close(); } catch (_) {}
      }
      final filesBox = await Hive.openBox('padlock_vault_files', encryptionCipher: HiveAesCipher(derivedKey));

      // Segunda camada, dentro do próprio cofre.
      final canary = filesBox.get('_vault_canary');
      if (firstTime) {
        await filesBox.put('_vault_canary', 'padlock_ok');
      } else if (canary != 'padlock_ok') {
        throw Exception('Vault Files data is corrupted (code was correct, but the vault file itself is damaged).');
      }

      await VaultFilesStore.migratePending(filesBox);
      VaultFilesKey.markUnlocked();

      if (mounted) {
        Navigator.of(context).pushReplacement(
          MaterialPageRoute(builder: (context) => const VaultFilesHomeScreen()),
        );
      }
    } catch (e) {
      if (firstTime) {
        await VaultFilesKey.wipe();
        await PadlockVaultKey.wipeKeyHash('padlock_vault_files_keyhash');
      }
      if (Hive.isBoxOpen('padlock_vault_files')) {
        try { await Hive.box('padlock_vault_files').close(); } catch (_) {}
      }
      if (mounted) {
        setState(() => _isProcessing = false);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('$e'.replaceFirst('Exception: ', ''))),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_isFirstTime == null) {
      return const Scaffold(
        backgroundColor: Colors.black,
        body: Center(child: CircularProgressIndicator(color: Colors.lightBlueAccent)),
      );
    }
    final firstTime = _isFirstTime!;
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        title: const Text('Secure Vault Files', style: TextStyle(color: Colors.lightBlueAccent)),
        iconTheme: const IconThemeData(color: Colors.lightBlueAccent),
      ),
      body: Container(
        decoration: const BoxDecoration(
          image: DecorationImage(
            image: AssetImage('assets/fundo matrix.png'),
            fit: BoxFit.cover,
            colorFilter: ColorFilter.mode(Colors.black87, BlendMode.darken),
          ),
        ),
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(28.0),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Icon(Icons.folder_copy_rounded, color: Colors.lightBlueAccent, size: 60),
                const SizedBox(height: 20),
                Text(
                  firstTime ? 'CREATE VAULT FILES CODE' : 'ENTER VAULT FILES CODE',
                  textAlign: TextAlign.center,
                  style: const TextStyle(color: Colors.white, fontSize: 18, fontWeight: FontWeight.bold, letterSpacing: 1.2),
                ),
                const SizedBox(height: 10),
                Text(
                  firstTime
                      ? 'This code is separate from your app unlock code. Anyone who knows your app code will NOT be able to open your photos and documents without it too.'
                      : 'Enter your Vault Files code to view your encrypted photos and documents.',
                  textAlign: TextAlign.center,
                  style: TextStyle(color: Colors.grey.shade400, fontSize: 12, height: 1.3),
                ),
                const SizedBox(height: 28),
                TextField(
                  controller: _codeController,
                  obscureText: _obscureText,
                  style: const TextStyle(color: Colors.white),
                  onSubmitted: (_) => _isProcessing ? null : _submit(),
                  decoration: InputDecoration(
                    labelText: firstTime ? 'Set Vault Files Code' : 'Vault Files Code',
                    labelStyle: const TextStyle(color: Colors.grey),
                    enabledBorder: OutlineInputBorder(borderSide: const BorderSide(color: Colors.grey), borderRadius: BorderRadius.circular(8)),
                    focusedBorder: OutlineInputBorder(borderSide: const BorderSide(color: Colors.lightBlueAccent), borderRadius: BorderRadius.circular(8)),
                    prefixIcon: const Icon(Icons.lock, color: Colors.lightBlueAccent),
                    suffixIcon: IconButton(
                      icon: Icon(_obscureText ? Icons.visibility_off : Icons.visibility, color: Colors.grey),
                      onPressed: () => setState(() => _obscureText = !_obscureText),
                    ),
                  ),
                ),
                const SizedBox(height: 24),
                SizedBox(
                  width: double.infinity,
                  height: 50,
                  child: ElevatedButton(
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.lightBlueAccent,
                      foregroundColor: Colors.black,
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                    ),
                    onPressed: _isProcessing ? null : _submit,
                    child: _isProcessing
                        ? const SizedBox(width: 22, height: 22, child: CircularProgressIndicator(strokeWidth: 2.5, color: Colors.black))
                        : Text(firstTime ? 'CREATE VAULT' : 'UNLOCK', style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

// ----------------------------------------------------
// SECURE VAULT FILES - lista de fotos/documentos
// ----------------------------------------------------
class VaultFilesHomeScreen extends StatefulWidget {
  const VaultFilesHomeScreen({super.key});

  @override
  State<VaultFilesHomeScreen> createState() => _VaultFilesHomeScreenState();
}

class _VaultFilesHomeScreenState extends State<VaultFilesHomeScreen> with SingleTickerProviderStateMixin {
  Timer? _sessionTimer;
  List<Map<String, dynamic>> _entries = [];
  late TabController _tabController;
  // IDs a meio de um envio - sem isto, o botão de enviar não dava nenhuma
  // pista visual de que já estava a trabalhar, e parecia "não fazer nada"
  // ao primeiro toque (convidando a carregar outra vez, e possivelmente
  // enviar o ficheiro em duplicado).
  final Set<String> _sendingIds = {};

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 3, vsync: this);
    _refresh();
    _sessionTimer = Timer.periodic(const Duration(seconds: 10), (_) {
      if (!VaultFilesKey.isUnlocked) _lockAndExit();
    });
  }

  @override
  void dispose() {
    _sessionTimer?.cancel();
    _tabController.dispose();
    super.dispose();
  }

  // Nunca misturar as tuas próprias fotos/documentos com os que outros te
  // enviaram - cada secção só mostra o que lhe pertence.
  List<Map<String, dynamic>> get _personalEntries =>
      _entries.where((e) => e['direction'] == 'local').toList();
  List<Map<String, dynamic>> get _receivedEntries =>
      _entries.where((e) => e['direction'] == 'received').toList();
  List<Map<String, dynamic>> get _sentEntries =>
      _entries.where((e) => e['direction'] == 'sent').toList();

  Box get _box => Hive.box('padlock_vault_files');

  void _refresh() {
    setState(() => _entries = VaultFilesStore.listEntries(_box));
  }

  void _lockAndExit() {
    // Evita mexer no Navigator ao mesmo tempo que outro bloqueio automático
    // (sessão principal, ou o Crypto Vault) - dois a fazê-lo em simultâneo
    // é a explicação mais provável para o ecrã a ficar todo branco e preso.
    if (PadlockNetwork.isPerformingAutoLock) return;
    PadlockNetwork.isPerformingAutoLock = true;
    VaultFilesKey.lock();
    if (mounted) Navigator.of(context).popUntil((route) => route.isFirst);
    // Este ecrã continua a existir por baixo (só saímos dele, a app não
    // termina) - por isso a flag tem de ser reposta, para o próximo
    // bloqueio automático voltar a funcionar mais tarde.
    Future.delayed(const Duration(seconds: 2), () => PadlockNetwork.isPerformingAutoLock = false);
  }

  Future<void> _takePhoto() async {
    final XFile? photo = await ImagePicker().pickImage(
      source: ImageSource.camera,
      imageQuality: 70,
      maxWidth: 1600,
    );
    if (photo == null) return;
    final bytes = await photo.readAsBytes();
    try { await File(photo.path).delete(); } catch (_) {}
    await VaultFilesStore.storeSent(peerId: '', fileName: 'photo.jpg', fileKind: 'photo', fileBytes: bytes, direction: 'local');
    _refresh();
  }

  static const _imageExtensions = {'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'heic', 'heif'};

  bool _looksLikeImage(String fileName) {
    final dot = fileName.lastIndexOf('.');
    if (dot == -1) return false;
    return _imageExtensions.contains(fileName.substring(dot + 1).toLowerCase());
  }

  Future<void> _importDocument() async {
    // allowMultiple para poder mandar várias fotos/documentos de uma vez -
    // antes só o primeiro ficheiro escolhido era guardado, os outros eram
    // descartados em silêncio.
    final result = await FilePicker.platform.pickFiles(withData: true, allowMultiple: true);
    if (result == null || result.files.isEmpty) return;

    int imported = 0, skipped = 0;
    for (final file in result.files) {
      Uint8List? bytes = file.bytes;
      if (bytes == null && file.path != null) {
        bytes = await File(file.path!).readAsBytes();
      }
      if (bytes == null) continue;
      if (bytes.length > kMaxVaultFileBytes) {
        skipped++;
        continue;
      }
      // Detecta pela extensão se é uma foto - antes, qualquer ficheiro
      // importado (mesmo um .jpg tirado da galeria) ficava marcado sempre
      // como "documento", sem pré-visualização de imagem nenhuma.
      final fileKind = _looksLikeImage(file.name) ? 'photo' : 'document';
      await VaultFilesStore.storeSent(peerId: '', fileName: file.name, fileKind: fileKind, fileBytes: bytes, direction: 'local');
      imported++;
    }
    _refresh();
    if (mounted && skipped > 0) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('$imported imported, $skipped skipped (max ${kMaxVaultFileBytes ~/ (1024 * 1024)}MB each).')),
      );
    }
  }

  // Escreve os bytes decifrados num ficheiro TEMPORÁRIO e abre a folha de
  // partilha nativa do Android (guardar na galeria, enviar por outra app,
  // etc.). O ficheiro temporário é apagado logo a seguir - nunca fica uma
  // cópia solta em texto simples no telemóvel depois de partilhar.
  Future<void> _exportEntry(Map<String, dynamic> entry, Uint8List bytes) async {
    final tempDir = await getTemporaryDirectory();
    final fileName = entry['fileName'] ?? 'padlock_file';
    final tempFile = File('${tempDir.path}/$fileName');
    try {
      await tempFile.writeAsBytes(bytes);
      await SharePlus.instance.share(ShareParams(files: [XFile(tempFile.path)]));
    } finally {
      try {
        if (await tempFile.exists()) await tempFile.delete();
      } catch (_) {}
    }
  }

  void _viewEntry(Map<String, dynamic> entry) {
    final bytes = VaultFilesStore.readData(_box, entry['id']);
    if (bytes == null) return;
    if (entry['fileKind'] == 'photo') {
      showDialog(
        context: context,
        builder: (ctx) => Dialog(
          backgroundColor: Colors.black,
          child: Stack(
            children: [
              InteractiveViewer(child: Image.memory(bytes)),
              Positioned(
                top: 8,
                right: 8,
                child: IconButton(
                  icon: const Icon(Icons.ios_share, color: Colors.white),
                  style: IconButton.styleFrom(backgroundColor: Colors.black.withValues(alpha: 0.5)),
                  onPressed: () => _exportEntry(entry, bytes),
                ),
              ),
            ],
          ),
        ),
      );
    } else {
      showDialog(
        context: context,
        builder: (ctx) => AlertDialog(
          backgroundColor: const Color(0xFF151515),
          title: Text(entry['fileName'] ?? 'Document', style: const TextStyle(color: Colors.white)),
          content: Text(
            'This document is stored encrypted in your Vault Files (${(bytes.length / 1024).toStringAsFixed(1)} KB). Use Export to save it back to your phone or share it.',
            style: const TextStyle(color: Colors.white70),
          ),
          actions: [
            TextButton(onPressed: () => _exportEntry(entry, bytes), child: const Text('Export', style: TextStyle(color: Colors.greenAccent))),
            TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Close', style: TextStyle(color: Colors.lightBlueAccent))),
          ],
        ),
      );
    }
  }

  Future<void> _sendEntry(Map<String, dynamic> entry) async {
    final contactsStr = Hive.box('padlock_vault').get('contacts');
    final List contacts = contactsStr != null ? jsonDecode(contactsStr) : [];
    if (contacts.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('No contacts yet.')));
      return;
    }
    final selected = await showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF151515),
        title: const Text('Send to...', style: TextStyle(color: Colors.white)),
        content: SizedBox(
          width: double.maxFinite,
          child: ListView(
            shrinkWrap: true,
            children: contacts.map<Widget>((c) {
              final id = c['id'] ?? c['name'];
              return ListTile(
                title: Text(id, style: const TextStyle(color: Colors.white, fontSize: 12)),
                onTap: () => Navigator.pop(ctx, id as String),
              );
            }).toList(),
          ),
        ),
      ),
    );
    if (selected == null) return;
    final bytes = VaultFilesStore.readData(_box, entry['id']);
    if (bytes == null) return;
    final entryId = entry['id'].toString();
    if (_sendingIds.contains(entryId)) return; // já a enviar - ignora um segundo toque
    setState(() => _sendingIds.add(entryId));
    try {
      await sendEncryptedFile(
        targetId: selected,
        fileBytes: bytes,
        fileName: entry['fileName'] ?? 'file',
        fileKind: entry['fileKind'] ?? 'document',
      );
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Sent.')));
    } catch (e) {
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Failed to send: $e')));
    } finally {
      if (mounted) setState(() => _sendingIds.remove(entryId));
    }
  }

  Future<void> _deleteEntry(Map<String, dynamic> entry) async {
    await VaultFilesStore.deleteEntry(_box, entry['id']);
    _refresh();
  }

  Widget _buildList(List<Map<String, dynamic>> entries, String emptyMessage) {
    if (entries.isEmpty) {
      return Center(
        child: Text(emptyMessage, textAlign: TextAlign.center, style: TextStyle(color: Colors.grey.shade500)),
      );
    }
    return ListView.builder(
      padding: const EdgeInsets.all(12),
      itemCount: entries.length,
      itemBuilder: (context, index) {
        final entry = entries[index];
        final isPhoto = entry['fileKind'] == 'photo';
        final direction = entry['direction'];
        final peer = (entry['peerId'] ?? '').toString();
        final subtitle = direction == 'received'
            ? 'Received from $peer'
            : direction == 'sent'
                ? 'Sent to $peer'
                : 'Stored locally — not sent to anyone yet';
        return Card(
          color: const Color(0xFF151515),
          margin: const EdgeInsets.only(bottom: 8),
          child: ListTile(
            leading: Icon(isPhoto ? Icons.image : Icons.description, color: Colors.lightBlueAccent),
            title: Text(entry['fileName'] ?? '', style: const TextStyle(color: Colors.white), overflow: TextOverflow.ellipsis),
            subtitle: Text(subtitle, style: const TextStyle(color: Colors.white54, fontSize: 11)),
            onTap: () => _viewEntry(entry),
            trailing: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                _sendingIds.contains(entry['id'].toString())
                    ? const SizedBox(width: 20, height: 20, child: Padding(padding: EdgeInsets.all(2), child: CircularProgressIndicator(strokeWidth: 2, color: Colors.greenAccent)))
                    : IconButton(icon: const Icon(Icons.send, color: Colors.greenAccent, size: 20), onPressed: () => _sendEntry(entry)),
                IconButton(icon: const Icon(Icons.delete, color: Colors.redAccent, size: 20), onPressed: () => _deleteEntry(entry)),
              ],
            ),
          ),
        );
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        title: const Text('Secure Vault Files', style: TextStyle(color: Colors.lightBlueAccent)),
        iconTheme: const IconThemeData(color: Colors.lightBlueAccent),
        actions: [
          IconButton(icon: const Icon(Icons.lock, color: Colors.lightBlueAccent), onPressed: _lockAndExit),
        ],
        bottom: TabBar(
          controller: _tabController,
          indicatorColor: Colors.lightBlueAccent,
          labelColor: Colors.lightBlueAccent,
          unselectedLabelColor: Colors.grey,
          tabs: const [
            Tab(text: 'Personal'),
            Tab(text: 'Received'),
            Tab(text: 'Sent'),
          ],
        ),
      ),
      body: Container(
        decoration: const BoxDecoration(
          image: DecorationImage(
            image: AssetImage('assets/fundo matrix.png'),
            fit: BoxFit.cover,
            colorFilter: ColorFilter.mode(Colors.black87, BlendMode.darken),
          ),
        ),
        child: TabBarView(
          controller: _tabController,
          children: [
            _buildList(_personalEntries, 'No personal files yet.\nUse the + button to take a photo or import a document.'),
            _buildList(_receivedEntries, 'Nothing received yet.'),
            _buildList(_sentEntries, 'Nothing sent yet.'),
          ],
        ),
      ),
      floatingActionButton: SpeedDialLikeFab(onPhoto: _takePhoto, onDocument: _importDocument),
    );
  }
}

// FAB simples com duas ações (tirar foto / importar documento) sem depender
// de pacotes extra de "speed dial".
class SpeedDialLikeFab extends StatelessWidget {
  final VoidCallback onPhoto;
  final VoidCallback onDocument;
  const SpeedDialLikeFab({super.key, required this.onPhoto, required this.onDocument});

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        FloatingActionButton(
          heroTag: 'vault_files_doc',
          backgroundColor: const Color(0xFF1e4d2b),
          onPressed: onDocument,
          child: const Icon(Icons.upload_file, color: Colors.white),
        ),
        const SizedBox(width: 12),
        FloatingActionButton(
          heroTag: 'vault_files_photo',
          backgroundColor: Colors.lightBlueAccent,
          onPressed: onPhoto,
          child: const Icon(Icons.camera_alt, color: Colors.black),
        ),
      ],
    );
  }
}

// ----------------------------------------------------
// SECURE CRYPTO VAULT - carteira não-custodial (FASE 1: gerar, receber, ver saldo)
// ----------------------------------------------------
class CryptoVaultGateScreen extends StatefulWidget {
  const CryptoVaultGateScreen({super.key});
  @override
  State<CryptoVaultGateScreen> createState() => _CryptoVaultGateScreenState();
}

class _CryptoVaultGateScreenState extends State<CryptoVaultGateScreen> {
  final TextEditingController _codeController = TextEditingController();
  final TextEditingController _mnemonicController = TextEditingController();
  bool _obscureText = true;
  bool _isProcessing = false;
  bool? _isFirstTime;
  bool _restoreMode = false;

  @override
  void initState() {
    super.initState();
    CryptoWalletKey.hasVault().then((has) {
      if (mounted) setState(() => _isFirstTime = !has);
    });
  }

  Future<void> _submit() async {
    final code = _codeController.text.trim();
    final firstTime = _isFirstTime == true;

    if (firstTime && _passphraseScore(code) < 1) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Code is too weak: use at least 10 characters and avoid repeated or sequential patterns.')),
      );
      return;
    }
    if (!firstTime && code.isEmpty) return;

    // Restaurar carteira existente (telemóvel novo, reinstalação): a frase
    // de recuperação tem de ser válida ANTES de sequer criar o cofre.
    bip39.Mnemonic? restoredMnemonic;
    if (firstTime && _restoreMode) {
      final sentence = _mnemonicController.text.trim().toLowerCase();
      try {
        restoredMnemonic = bip39.Mnemonic.fromSentence(sentence, bip39.Language.english);
      } catch (e) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Invalid recovery phrase - check the words and try again.')),
        );
        return;
      }
    }

    setState(() => _isProcessing = true);
    try {
      final salt = firstTime ? await CryptoWalletKey.createSalt() : await CryptoWalletKey.getSalt();
      if (salt == null) throw Exception('Crypto Vault not initialized on this device.');

      final derivedKey = await PadlockVaultKey.deriveKey(code, salt);

      // Nunca abrir o Hive com uma chave ainda não confirmada - mesma razão
      // dos outros dois cofres: pode não dar erro (só lixo válido-parecido),
      // e uma abertura falhada pode deixar a caixa presa a recusar até a
      // chave certa depois.
      if (!firstTime) {
        final validKey = await PadlockVaultKey.verifyKeyHash('padlock_crypto_vault_keyhash', derivedKey);
        if (!validKey) {
          throw Exception('Invalid Crypto Vault code.');
        }
      }

      if (Hive.isBoxOpen('padlock_crypto_vault')) {
        try { await Hive.box('padlock_crypto_vault').close(); } catch (_) {}
      }
      final walletBox = await Hive.openBox('padlock_crypto_vault', encryptionCipher: HiveAesCipher(derivedKey));

      // Segunda camada, dentro do próprio cofre.
      final canary = walletBox.get('_vault_canary');
      if (!firstTime && canary != 'padlock_ok') {
        throw Exception('Crypto Vault data is corrupted (code was correct, but the vault file itself is damaged).');
      }

      CryptoWalletKey.markUnlocked();

      if (firstTime) {
        await PadlockVaultKey.storeKeyHash('padlock_crypto_vault_keyhash', derivedKey);
        await walletBox.put('_vault_canary', 'padlock_ok');
        if (restoredMnemonic != null) {
          // Restauro: a frase já é conhecida do utilizador, não voltamos a mostrá-la.
          await PadlockWallet.storeMnemonic(walletBox, restoredMnemonic.sentence);
        } else {
          final mnemonic = PadlockWallet.generateMnemonic();
          await PadlockWallet.storeMnemonic(walletBox, mnemonic.sentence);
          if (mounted) {
            await Navigator.of(context).push(
              MaterialPageRoute(builder: (context) => MnemonicRevealScreen(sentence: mnemonic.sentence)),
            );
          }
        }
      }

      if (mounted) {
        Navigator.of(context).pushReplacement(
          MaterialPageRoute(builder: (context) => const CryptoVaultHomeScreen()),
        );
      }
    } catch (e) {
      if (firstTime) {
        await CryptoWalletKey.wipe();
        await PadlockVaultKey.wipeKeyHash('padlock_crypto_vault_keyhash');
      }
      if (Hive.isBoxOpen('padlock_crypto_vault')) {
        try { await Hive.box('padlock_crypto_vault').close(); } catch (_) {}
      }
      if (mounted) {
        setState(() => _isProcessing = false);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('$e'.replaceFirst('Exception: ', ''))),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_isFirstTime == null) {
      return const Scaffold(
        backgroundColor: Colors.black,
        body: Center(child: CircularProgressIndicator(color: Colors.greenAccent)),
      );
    }
    final firstTime = _isFirstTime!;
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        title: const Text('Secure Crypto Vault', style: TextStyle(color: Colors.greenAccent)),
        iconTheme: const IconThemeData(color: Colors.greenAccent),
      ),
      body: Container(
        decoration: const BoxDecoration(
          image: DecorationImage(
            image: AssetImage('assets/fundo matrix.png'),
            fit: BoxFit.cover,
            colorFilter: ColorFilter.mode(Colors.black87, BlendMode.darken),
          ),
        ),
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(28.0),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Text('💎', style: TextStyle(fontSize: 60)),
                const SizedBox(height: 20),
                Text(
                  firstTime ? 'CREATE CRYPTO VAULT CODE' : 'ENTER CRYPTO VAULT CODE',
                  textAlign: TextAlign.center,
                  style: const TextStyle(color: Colors.white, fontSize: 18, fontWeight: FontWeight.bold, letterSpacing: 1.2),
                ),
                const SizedBox(height: 10),
                Text(
                  firstTime
                      ? 'This code is separate from your app and Vault Files codes. It protects a brand-new, non-custodial wallet that only you control.'
                      : 'Enter your Crypto Vault code to access your wallet.',
                  textAlign: TextAlign.center,
                  style: TextStyle(color: Colors.grey.shade400, fontSize: 12, height: 1.3),
                ),
                if (firstTime) ...[
                  const SizedBox(height: 8),
                  TextButton(
                    onPressed: () => setState(() => _restoreMode = !_restoreMode),
                    child: Text(
                      _restoreMode ? '← Create a new wallet instead' : 'I already have a recovery phrase (lost phone / reinstall)',
                      style: const TextStyle(color: Colors.lightBlueAccent, fontSize: 12),
                    ),
                  ),
                ],
                if (_restoreMode) ...[
                  const SizedBox(height: 8),
                  TextField(
                    controller: _mnemonicController,
                    maxLines: 3,
                    style: const TextStyle(color: Colors.white),
                    decoration: InputDecoration(
                      labelText: 'Your 12-word recovery phrase',
                      labelStyle: const TextStyle(color: Colors.grey),
                      hintText: 'word1 word2 word3 ...',
                      hintStyle: TextStyle(color: Colors.grey.shade700),
                      enabledBorder: OutlineInputBorder(borderSide: const BorderSide(color: Colors.grey), borderRadius: BorderRadius.circular(8)),
                      focusedBorder: const OutlineInputBorder(borderSide: BorderSide(color: Colors.lightBlueAccent), borderRadius: BorderRadius.all(Radius.circular(8))),
                    ),
                  ),
                ],
                const SizedBox(height: 20),
                TextField(
                  controller: _codeController,
                  obscureText: _obscureText,
                  style: const TextStyle(color: Colors.white),
                  decoration: InputDecoration(
                    labelText: firstTime ? 'Set Crypto Vault Code (for THIS device)' : 'Crypto Vault Code',
                    labelStyle: const TextStyle(color: Colors.grey),
                    enabledBorder: OutlineInputBorder(borderSide: const BorderSide(color: Colors.grey), borderRadius: BorderRadius.circular(8)),
                    focusedBorder: const OutlineInputBorder(borderSide: BorderSide(color: Colors.lightBlueAccent), borderRadius: BorderRadius.all(Radius.circular(8))),
                    prefixIcon: const Icon(Icons.lock, color: Colors.lightBlueAccent),
                    suffixIcon: IconButton(
                      icon: Icon(_obscureText ? Icons.visibility_off : Icons.visibility, color: Colors.grey),
                      onPressed: () => setState(() => _obscureText = !_obscureText),
                    ),
                  ),
                ),
                const SizedBox(height: 24),
                SizedBox(
                  width: double.infinity,
                  height: 50,
                  child: DecoratedBox(
                    decoration: BoxDecoration(
                      borderRadius: BorderRadius.circular(8),
                      gradient: const LinearGradient(colors: [Color(0xFF1e4d2b), Color(0xFF0a1a12)]),
                      border: Border.all(color: Colors.greenAccent.withValues(alpha: 0.6)),
                    ),
                    child: ElevatedButton(
                      style: ElevatedButton.styleFrom(backgroundColor: Colors.transparent, shadowColor: Colors.transparent, foregroundColor: Colors.white),
                      onPressed: _isProcessing ? null : _submit,
                      child: _isProcessing
                          ? const SizedBox(width: 22, height: 22, child: CircularProgressIndicator(strokeWidth: 2.5, color: Colors.greenAccent))
                          : Text(
                              firstTime ? (_restoreMode ? 'RESTORE WALLET' : 'CREATE WALLET') : 'UNLOCK',
                              style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
                            ),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

// Mostra a frase-semente UMA VEZ, obrigando confirmação de que foi guardada
// em papel/offline antes de avançar - tal como qualquer carteira a sério
// (MetaMask, Trust Wallet). Sem isto, perder o telemóvel = perder os fundos
// para sempre, sem hipótese de recuperação - a Padlock nunca guarda cópia.
class MnemonicRevealScreen extends StatefulWidget {
  final String sentence;
  const MnemonicRevealScreen({super.key, required this.sentence});
  @override
  State<MnemonicRevealScreen> createState() => _MnemonicRevealScreenState();
}

class _MnemonicRevealScreenState extends State<MnemonicRevealScreen> {
  bool _confirmed = false;

  @override
  Widget build(BuildContext context) {
    final words = widget.sentence.split(' ');
    return PopScope(
      canPop: false,
      child: Scaffold(
        backgroundColor: Colors.black,
        appBar: AppBar(
          backgroundColor: Colors.transparent,
          automaticallyImplyLeading: false,
          title: const Text('Your Recovery Phrase', style: TextStyle(color: Colors.greenAccent)),
        ),
        // Sem SafeArea, o botão CONTINUE e a checkbox ficavam por baixo da
        // barra de gestos/botões do Android em telemóveis sem botões físicos.
        body: SafeArea(
          child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            children: [
              const Text(
                '⚠️ Write these 12 words down on paper, in order, and keep them somewhere safe and offline. Anyone with these words can steal your funds. Padlock does NOT store this phrase anywhere and cannot recover it for you.',
                style: TextStyle(color: Colors.redAccent, fontSize: 12, height: 1.4),
              ),
              const SizedBox(height: 20),
              Expanded(
                child: GridView.builder(
                  gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(crossAxisCount: 3, childAspectRatio: 2.5, crossAxisSpacing: 8, mainAxisSpacing: 8),
                  itemCount: words.length,
                  itemBuilder: (context, index) => Container(
                    decoration: BoxDecoration(
                      color: const Color(0xFF151515),
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: Colors.greenAccent.withValues(alpha: 0.4)),
                    ),
                    alignment: Alignment.center,
                    child: Text('${index + 1}. ${words[index]}', style: const TextStyle(color: Colors.white, fontSize: 13)),
                  ),
                ),
              ),
              CheckboxListTile(
                value: _confirmed,
                onChanged: (v) => setState(() => _confirmed = v ?? false),
                title: const Text('I have written down these words and stored them safely offline.', style: TextStyle(color: Colors.white70, fontSize: 12)),
                activeColor: Colors.greenAccent,
                controlAffinity: ListTileControlAffinity.leading,
              ),
              SizedBox(
                width: double.infinity,
                height: 50,
                child: DecoratedBox(
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(8),
                    gradient: _confirmed
                        ? const LinearGradient(colors: [Color(0xFF1e4d2b), Color(0xFF0a1a12)])
                        : null,
                    color: _confirmed ? null : const Color(0xFF1a1a1a),
                    border: Border.all(color: Colors.greenAccent.withValues(alpha: _confirmed ? 0.7 : 0.2)),
                  ),
                  child: ElevatedButton(
                    style: ElevatedButton.styleFrom(backgroundColor: Colors.transparent, shadowColor: Colors.transparent, foregroundColor: Colors.white),
                    onPressed: _confirmed ? () => Navigator.pop(context) : null,
                    child: const Text('CONTINUE', style: TextStyle(fontWeight: FontWeight.bold)),
                  ),
                ),
              ),
            ],
          ),
          ),
        ),
      ),
    );
  }
}

// SECURE CRYPTO VAULT - saldo e receção. Enviar fica para a fase 2, depois
// de confirmares que isto funciona bem num telemóvel real.
class CryptoVaultHomeScreen extends StatefulWidget {
  const CryptoVaultHomeScreen({super.key});
  @override
  State<CryptoVaultHomeScreen> createState() => _CryptoVaultHomeScreenState();
}

class _CryptoVaultHomeScreenState extends State<CryptoVaultHomeScreen> {
  Timer? _sessionTimer;
  EthereumAddress? _address;
  EthPrivateKey? _credentials;
  // Uma entrada por moeda suportada: texto do saldo já formatado + cotação
  // USD (null enquanto não chegou/falhou), para mostrar "≈ $X.XX" por baixo.
  final Map<String, String> _balanceText = {for (final t in PadlockWallet.supportedTokens) t.symbol: 'Loading...'};
  final Map<String, double?> _usdPrice = {for (final t in PadlockWallet.supportedTokens) t.symbol: null};
  bool _isRefreshing = false;

  @override
  void initState() {
    super.initState();
    _loadWallet();
    _sessionTimer = Timer.periodic(const Duration(seconds: 10), (_) {
      if (!CryptoWalletKey.isUnlocked) _lockAndExit();
    });
  }

  @override
  void dispose() {
    _sessionTimer?.cancel();
    super.dispose();
  }

  Box get _box => Hive.box('padlock_crypto_vault');

  void _lockAndExit() {
    // Mesma razão do Vault Files: evita dois bloqueios automáticos a mexer
    // no Navigator ao mesmo tempo (a explicação mais provável para o ecrã
    // ficar todo branco e preso).
    if (PadlockNetwork.isPerformingAutoLock) return;
    PadlockNetwork.isPerformingAutoLock = true;
    CryptoWalletKey.lock();
    if (mounted) Navigator.of(context).popUntil((route) => route.isFirst);
    Future.delayed(const Duration(seconds: 2), () => PadlockNetwork.isPerformingAutoLock = false);
  }

  Future<void> _loadWallet() async {
    final sentence = PadlockWallet.readMnemonic(_box);
    if (sentence == null) return;
    final mnemonic = bip39.Mnemonic.fromSentence(sentence, bip39.Language.english);
    final credentials = PadlockWallet.credentialsFromMnemonic(mnemonic);
    setState(() {
      _address = credentials.address;
      _credentials = credentials;
    });
    await _refreshBalance();
  }

  Future<void> _refreshBalance() async {
    if (_address == null) return;
    setState(() => _isRefreshing = true);
    await Future.wait(PadlockWallet.supportedTokens.map((token) async {
      try {
        final raw = await PadlockWallet.getTokenBalanceRaw(_address!, token);
        final price = await PadlockWallet.fetchUsdPrice(token);
        if (mounted) {
          setState(() {
            _balanceText[token.symbol] = PadlockWallet.formatUnits(raw, token.decimals);
            _usdPrice[token.symbol] = price;
          });
        }
      } catch (e) {
        print('Erro ao carregar saldo de ${token.symbol} (ambas as RPCs falharam): $e');
        if (mounted) setState(() => _balanceText[token.symbol] = 'Could not load balance');
      }
    }));
    if (mounted) setState(() => _isRefreshing = false);
  }

  void _showQr() {
    if (_address == null) return;
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF151515),
        shape: RoundedRectangleBorder(side: const BorderSide(color: Colors.greenAccent, width: 1), borderRadius: BorderRadius.circular(12)),
        title: const Text('Receive', style: TextStyle(color: Colors.greenAccent)),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              padding: const EdgeInsets.all(12),
              color: Colors.white,
              child: QrImageView(data: _address!.hexEip55, size: 200),
            ),
            const SizedBox(height: 16),
            const Text('Scanning or sharing this code gives out your wallet ADDRESS only - never your recovery phrase.', textAlign: TextAlign.center, style: TextStyle(color: Colors.grey, fontSize: 10)),
            const SizedBox(height: 10),
            SelectableText(_address!.hexEip55, style: const TextStyle(color: Colors.white, fontSize: 11)),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () {
              Clipboard.setData(ClipboardData(text: _address!.hexEip55));
              ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Address copied.')));
            },
            child: const Text('COPY', style: TextStyle(color: Colors.lightBlueAccent)),
          ),
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('CLOSE', style: TextStyle(color: Colors.grey))),
        ],
      ),
    );
  }

  Future<void> _openSendScreen() async {
    if (_address == null || _credentials == null) return;
    final result = await Navigator.of(context).push<bool>(
      MaterialPageRoute(
        builder: (context) => CryptoSendScreen(credentials: _credentials!, fromAddress: _address!),
      ),
    );
    if (result == true) await _refreshBalance();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        title: const Text('Secure Crypto Vault', style: TextStyle(color: Colors.greenAccent)),
        iconTheme: const IconThemeData(color: Colors.greenAccent),
        actions: [
          IconButton(icon: const Icon(Icons.lock, color: Colors.greenAccent), onPressed: _lockAndExit),
        ],
      ),
      body: Container(
        decoration: const BoxDecoration(
          image: DecorationImage(
            image: AssetImage('assets/fundo matrix.png'),
            fit: BoxFit.cover,
            colorFilter: ColorFilter.mode(Colors.black87, BlendMode.darken),
          ),
        ),
        child: SafeArea(
          child: Padding(
            padding: const EdgeInsets.all(20),
            child: Column(
              children: [
                Container(
                  padding: const EdgeInsets.symmetric(vertical: 6, horizontal: 12),
                  decoration: BoxDecoration(color: Colors.redAccent.withValues(alpha: 0.15), borderRadius: BorderRadius.circular(8)),
                  child: const Text('⚠️ TESTNET (Polygon Amoy) - these are NOT real funds.', style: TextStyle(color: Colors.redAccent, fontSize: 11, fontWeight: FontWeight.bold)),
                ),
                const SizedBox(height: 30),
                // "Tubo" espelhado verde, tal como no Perfil - a moldura da
                // carteira, para o topo do Crypto Vault seguir o mesmo
                // estilo visual do resto da app.
                Container(
                  width: 88,
                  height: 88,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    gradient: const LinearGradient(
                      begin: Alignment.topLeft,
                      end: Alignment.bottomRight,
                      colors: [Color(0xFF1e4d2b), Color(0xFF0a1a12)],
                    ),
                    border: Border.all(color: Colors.greenAccent.withValues(alpha: 0.7), width: 1.5),
                    boxShadow: [BoxShadow(color: Colors.greenAccent.withValues(alpha: 0.3), blurRadius: 16, spreadRadius: 1)],
                  ),
                  child: const Icon(Icons.diamond, color: Colors.lightBlueAccent, size: 34),
                ),
                const SizedBox(height: 20),
                Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    const Text('Balances', style: TextStyle(color: Colors.grey, fontSize: 12)),
                    IconButton(
                      icon: _isRefreshing
                          ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.lightBlueAccent))
                          : const Icon(Icons.refresh, color: Colors.lightBlueAccent, size: 18),
                      onPressed: _isRefreshing ? null : _refreshBalance,
                    ),
                  ],
                ),
                const SizedBox(height: 4),
                ...PadlockWallet.supportedTokens.map((token) {
                  final priceKnown = _usdPrice[token.symbol];
                  final numericBalance = double.tryParse(_balanceText[token.symbol] ?? '');
                  final usdText = (priceKnown != null && numericBalance != null)
                      ? '≈ \$${(numericBalance * priceKnown).toStringAsFixed(2)}'
                      : null;
                  return Padding(
                    padding: const EdgeInsets.symmetric(vertical: 6),
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Text('${token.symbol}: ', style: const TextStyle(color: Colors.lightBlueAccent, fontSize: 16, fontWeight: FontWeight.bold)),
                        Flexible(
                          child: Text(
                            _balanceText[token.symbol] ?? 'Loading...',
                            style: const TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold),
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                        if (usdText != null) ...[
                          const SizedBox(width: 6),
                          Text(usdText, style: const TextStyle(color: Colors.grey, fontSize: 12)),
                        ],
                      ],
                    ),
                  );
                }),
                const SizedBox(height: 20),
                if (_address != null)
                  Text(_address!.hexEip55, style: const TextStyle(color: Colors.white54, fontSize: 11), textAlign: TextAlign.center),
                const SizedBox(height: 30),
                Row(
                  children: [
                    Expanded(
                      child: DecoratedBox(
                        decoration: BoxDecoration(
                          borderRadius: BorderRadius.circular(8),
                          gradient: const LinearGradient(colors: [Color(0xFF1e4d2b), Color(0xFF0a1a12)]),
                          border: Border.all(color: Colors.greenAccent.withValues(alpha: 0.6)),
                        ),
                        child: ElevatedButton.icon(
                          style: ElevatedButton.styleFrom(backgroundColor: Colors.transparent, shadowColor: Colors.transparent, foregroundColor: Colors.white, padding: const EdgeInsets.symmetric(vertical: 14)),
                          onPressed: _showQr,
                          icon: const Icon(Icons.qr_code),
                          label: const Text('RECEIVE'),
                        ),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: DecoratedBox(
                        decoration: BoxDecoration(
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(color: Colors.lightBlueAccent.withValues(alpha: 0.8), width: 1.5),
                        ),
                        child: ElevatedButton.icon(
                          style: ElevatedButton.styleFrom(backgroundColor: Colors.transparent, shadowColor: Colors.transparent, foregroundColor: Colors.lightBlueAccent, padding: const EdgeInsets.symmetric(vertical: 14)),
                          onPressed: (_address != null && _credentials != null) ? _openSendScreen : null,
                          icon: const Icon(Icons.send),
                          label: const Text('SEND'),
                        ),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

// Ecrã de envio: cola/digita ou digitaliza (câmara) o endereço de destino,
// escreve o montante e confirma. Testnet apenas (POL sem valor real) - por
// isso a assinatura e broadcast acontecem já aqui, sem uma segunda fase de
// confirmação extra, ao contrário do que aconteceria numa rede a sério.
class CryptoSendScreen extends StatefulWidget {
  final EthPrivateKey credentials;
  final EthereumAddress fromAddress;
  const CryptoSendScreen({super.key, required this.credentials, required this.fromAddress});
  @override
  State<CryptoSendScreen> createState() => _CryptoSendScreenState();
}

class _CryptoSendScreenState extends State<CryptoSendScreen> {
  final TextEditingController _addressController = TextEditingController();
  final TextEditingController _amountController = TextEditingController();
  bool _isSending = false;
  CryptoToken _selectedToken = PadlockWallet.supportedTokens.first;
  bool _amountInUsd = false;
  double? _price; // cotação USD da moeda escolhida - null enquanto carrega/falha

  @override
  void initState() {
    super.initState();
    _fetchPrice();
    _amountController.addListener(() => setState(() {}));
  }

  Future<void> _fetchPrice() async {
    setState(() => _price = null);
    final p = await PadlockWallet.fetchUsdPrice(_selectedToken);
    if (mounted) setState(() => _price = p);
  }

  // Texto de ajuda por baixo do campo de montante: mostra a conversão para o
  // outro lado (USD <-> cripto), consoante o que a pessoa está a escrever.
  String? get _conversionHint {
    final typed = double.tryParse(_amountController.text.trim().replaceAll(',', '.'));
    if (typed == null || _price == null) return null;
    if (_amountInUsd) {
      return '≈ ${(typed / _price!).toStringAsFixed(6)} ${_selectedToken.symbol}';
    }
    return '≈ \$${(typed * _price!).toStringAsFixed(2)}';
  }

  Future<void> _scanAddress() async {
    try {
      final camStatus = await Permission.camera.request();
      if (!camStatus.isGranted) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('Camera permission denied. Enable it in phone Settings > Apps > Padlock > Permissions.')),
          );
        }
        return;
      }
      bool scanned = false;
      await Navigator.push(
        context,
        MaterialPageRoute(
          builder: (context) => Scaffold(
            appBar: AppBar(title: const Text('Scan Wallet Address')),
            body: MobileScanner(
              onDetect: (capture) {
                if (scanned) return;
                for (final barcode in capture.barcodes) {
                  if (barcode.rawValue != null) {
                    scanned = true;
                    _addressController.text = barcode.rawValue!;
                    Navigator.pop(context);
                    break;
                  }
                }
              },
            ),
          ),
        ),
      );
    } catch (e) {
      print('Scan Error: $e');
    }
  }

  Future<void> _confirmSend() async {
    final addressText = _addressController.text.trim();
    final amountText = _amountController.text.trim().replaceAll(',', '.');

    EthereumAddress toAddress;
    try {
      toAddress = EthereumAddress.fromHex(addressText);
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Invalid wallet address.')),
      );
      return;
    }

    final typedValue = double.tryParse(amountText);
    if (typedValue == null || typedValue <= 0) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Enter a valid amount.')),
      );
      return;
    }

    // Se o montante foi escrito em dólares, converte para a moeda ANTES de
    // formar a transação - só a partir daqui é que o valor tem de ser exato
    // ao cêntimo do token (a conversão $ -> cripto já é, por natureza, uma
    // estimativa, dado que a cotação nunca é perfeitamente instantânea).
    String cryptoAmountText;
    if (_amountInUsd) {
      if (_price == null) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Price not loaded yet - try again in a moment.')),
        );
        return;
      }
      cryptoAmountText = (typedValue / _price!).toStringAsFixed(_selectedToken.decimals.clamp(0, 8));
    } else {
      cryptoAmountText = amountText;
    }

    setState(() => _isSending = true);
    try {
      final rawAmount = PadlockWallet.parseUnits(cryptoAmountText, _selectedToken.decimals);
      final String txHash;
      if (_selectedToken.isNative) {
        txHash = await PadlockWallet.sendTransaction(
          credentials: widget.credentials,
          to: toAddress,
          amount: EtherAmount.fromBigInt(EtherUnit.wei, rawAmount),
        );
      } else {
        txHash = await PadlockWallet.sendErc20(
          credentials: widget.credentials,
          to: toAddress,
          token: _selectedToken.contractAddress!,
          rawAmount: rawAmount,
        );
      }
      if (mounted) {
        showDialog(
          context: context,
          builder: (ctx) => AlertDialog(
            backgroundColor: const Color(0xFF151515),
            shape: RoundedRectangleBorder(side: const BorderSide(color: Colors.greenAccent, width: 1), borderRadius: BorderRadius.circular(12)),
            title: const Text('Transaction Sent', style: TextStyle(color: Colors.greenAccent)),
            content: SelectableText(txHash, style: const TextStyle(color: Colors.white70, fontSize: 12)),
            actions: [
              TextButton(
                onPressed: () {
                  Navigator.pop(ctx);
                  Navigator.pop(context, true);
                },
                child: const Text('DONE', style: TextStyle(color: Colors.lightBlueAccent)),
              ),
            ],
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Send failed: $e')),
        );
      }
    } finally {
      if (mounted) setState(() => _isSending = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        title: const Text('Send', style: TextStyle(color: Colors.lightBlueAccent)),
        iconTheme: const IconThemeData(color: Colors.lightBlueAccent),
      ),
      body: Container(
        decoration: const BoxDecoration(
          image: DecorationImage(
            image: AssetImage('assets/fundo matrix.png'),
            fit: BoxFit.cover,
            colorFilter: ColorFilter.mode(Colors.black87, BlendMode.darken),
          ),
        ),
        child: SafeArea(
          child: Padding(
            padding: const EdgeInsets.all(20),
            child: Column(
              children: [
                Container(
                  padding: const EdgeInsets.symmetric(vertical: 6, horizontal: 12),
                  decoration: BoxDecoration(color: Colors.redAccent.withValues(alpha: 0.15), borderRadius: BorderRadius.circular(8)),
                  child: const Text('⚠️ TESTNET (Polygon Amoy) - these are NOT real funds.', style: TextStyle(color: Colors.redAccent, fontSize: 11, fontWeight: FontWeight.bold)),
                ),
                const SizedBox(height: 24),
                TextField(
                  controller: _addressController,
                  style: const TextStyle(color: Colors.white, fontSize: 12),
                  decoration: InputDecoration(
                    labelText: 'Recipient wallet address',
                    labelStyle: const TextStyle(color: Colors.grey),
                    enabledBorder: OutlineInputBorder(borderSide: const BorderSide(color: Colors.grey), borderRadius: BorderRadius.circular(8)),
                    focusedBorder: const OutlineInputBorder(borderSide: BorderSide(color: Colors.lightBlueAccent), borderRadius: BorderRadius.all(Radius.circular(8))),
                    suffixIcon: IconButton(
                      icon: const Icon(Icons.qr_code_scanner, color: Colors.lightBlueAccent),
                      onPressed: _scanAddress,
                    ),
                  ),
                ),
                const SizedBox(height: 20),
                // Escolha da moeda a enviar - cada uma tem o seu próprio saldo
                // e (se aplicável) a sua própria cotação USD.
                DropdownButtonFormField<CryptoToken>(
                  initialValue: _selectedToken,
                  dropdownColor: const Color(0xFF151515),
                  style: const TextStyle(color: Colors.white),
                  decoration: InputDecoration(
                    labelText: 'Coin',
                    labelStyle: const TextStyle(color: Colors.grey),
                    enabledBorder: OutlineInputBorder(borderSide: const BorderSide(color: Colors.grey), borderRadius: BorderRadius.circular(8)),
                    focusedBorder: const OutlineInputBorder(borderSide: BorderSide(color: Colors.lightBlueAccent), borderRadius: BorderRadius.all(Radius.circular(8))),
                  ),
                  items: PadlockWallet.supportedTokens
                      .map((token) => DropdownMenuItem(value: token, child: Text('${token.symbol} - ${token.name}')))
                      .toList(),
                  onChanged: (token) {
                    if (token == null) return;
                    setState(() => _selectedToken = token);
                    _fetchPrice();
                  },
                ),
                const SizedBox(height: 12),
                // Alternar entre escrever o montante na própria moeda ou em
                // dólares (a app converte automaticamente para a moeda).
                Row(
                  children: [
                    const Text('Amount in:', style: TextStyle(color: Colors.grey, fontSize: 12)),
                    const SizedBox(width: 10),
                    ChoiceChip(
                      label: Text(_selectedToken.symbol),
                      selected: !_amountInUsd,
                      onSelected: (_) => setState(() => _amountInUsd = false),
                      selectedColor: Colors.lightBlueAccent,
                      labelStyle: TextStyle(color: !_amountInUsd ? Colors.black : Colors.white70),
                      backgroundColor: const Color(0xFF1a1a1a),
                    ),
                    const SizedBox(width: 8),
                    ChoiceChip(
                      label: const Text('USD'),
                      selected: _amountInUsd,
                      onSelected: (_) => setState(() => _amountInUsd = true),
                      selectedColor: Colors.lightBlueAccent,
                      labelStyle: TextStyle(color: _amountInUsd ? Colors.black : Colors.white70),
                      backgroundColor: const Color(0xFF1a1a1a),
                    ),
                  ],
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: _amountController,
                  keyboardType: const TextInputType.numberWithOptions(decimal: true),
                  style: const TextStyle(color: Colors.white),
                  decoration: InputDecoration(
                    labelText: _amountInUsd ? 'Amount (USD)' : 'Amount (${_selectedToken.symbol})',
                    labelStyle: const TextStyle(color: Colors.grey),
                    enabledBorder: OutlineInputBorder(borderSide: const BorderSide(color: Colors.grey), borderRadius: BorderRadius.circular(8)),
                    focusedBorder: const OutlineInputBorder(borderSide: BorderSide(color: Colors.lightBlueAccent), borderRadius: BorderRadius.all(Radius.circular(8))),
                    helperText: _price == null
                        ? 'Loading price...'
                        : (_conversionHint ?? 'Price: \$${_price!.toStringAsFixed(_price! < 1 ? 6 : 2)} / ${_selectedToken.symbol}'),
                    helperStyle: const TextStyle(color: Colors.grey, fontSize: 11),
                  ),
                ),
                const SizedBox(height: 28),
                SizedBox(
                  width: double.infinity,
                  height: 50,
                  child: DecoratedBox(
                    decoration: BoxDecoration(
                      borderRadius: BorderRadius.circular(8),
                      gradient: const LinearGradient(colors: [Color(0xFF1e4d2b), Color(0xFF0a1a12)]),
                      border: Border.all(color: Colors.greenAccent.withValues(alpha: 0.6)),
                    ),
                    child: ElevatedButton(
                      style: ElevatedButton.styleFrom(backgroundColor: Colors.transparent, shadowColor: Colors.transparent, foregroundColor: Colors.white),
                      onPressed: _isSending ? null : _confirmSend,
                      child: _isSending
                          ? const SizedBox(width: 22, height: 22, child: CircularProgressIndicator(strokeWidth: 2.5, color: Colors.greenAccent))
                          : const Text('CONFIRM & SEND', style: TextStyle(fontWeight: FontWeight.bold)),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class MatrixBackgroundPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final random = Random(42);
    const double columnWidth = 22.0;

    for (double x = 0; x < size.width; x += columnWidth) {
      for (double y = 0; y < size.height; y += 28) {
        if (random.nextDouble() > 0.55) {
          final textPainter = TextPainter(
            text: TextSpan(
              text: random.nextBool() ? '1' : '0',
              style: TextStyle(
                // Variação suave de opacidade: umas partes mais visíveis, outras mais apagadas
                color: const Color(0xFF00FF66).withValues(alpha: random.nextDouble() * 0.7 + 0.3),
                fontSize: 12,
                fontFamily: 'monospace',
              ),
            ),
            textDirection: TextDirection.ltr,
          );
          textPainter.layout();
          textPainter.paint(canvas, Offset(x + random.nextDouble() * 4, y));
        }
      }
    }
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}

void openCryptoVault(BuildContext context) {
  if (PremiumService.isPremium) {
    Navigator.of(context).push(
      MaterialPageRoute(builder: (context) => const CryptoVaultGateScreen()),
    );
  } else {
    showPremiumRequiredDialog(context);
  }
}

// ATENÇÃO - REMOVER ANTES DE PUBLICAR NA PLAY STORE: código de testador
// temporário para o programador conseguir entrar no Crypto Vault sem
// precisar de configurar já as subscrições na Google Play Console. Só
// desbloqueia o ecrã do Crypto Vault (não é uma falha de segurança das
// mensagens/chamadas - é só a barreira de pagamento). Ainda assim, quem
// tiver este código de código-fonte consegue Premium grátis, por isso tem
// de sair antes de a app ir para produção a sério.
const String _kCryptoVaultTesterCode = 'PADLOCK_TESTER_2026';

void _showCryptoVaultTesterUnlock(BuildContext dialogContext) {
  final controller = TextEditingController();
  showDialog(
    context: dialogContext,
    builder: (ctx) => AlertDialog(
      backgroundColor: const Color(0xFF151515),
      shape: RoundedRectangleBorder(
        side: const BorderSide(color: Colors.amber, width: 1.5),
        borderRadius: BorderRadius.circular(12),
      ),
      title: const Text('Código de Testador', style: TextStyle(color: Colors.amber, fontSize: 14)),
      content: TextField(
        controller: controller,
        obscureText: true,
        style: const TextStyle(color: Colors.white),
        decoration: const InputDecoration(hintText: 'Código', hintStyle: TextStyle(color: Colors.grey)),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(ctx),
          child: const Text('CANCEL', style: TextStyle(color: Colors.grey)),
        ),
        TextButton(
          onPressed: () async {
            if (controller.text.trim() == _kCryptoVaultTesterCode) {
              await Hive.box('padlock_vault').put('is_premium', true);
              if (ctx.mounted) Navigator.pop(ctx);
              if (dialogContext.mounted) {
                Navigator.pop(dialogContext); // fecha o dialog "PREMIUM REQUIRED"
                Navigator.of(dialogContext).push(
                  MaterialPageRoute(builder: (context) => const CryptoVaultGateScreen()),
                );
              }
            } else {
              Navigator.pop(ctx);
            }
          },
          child: const Text('UNLOCK', style: TextStyle(color: Colors.amber, fontWeight: FontWeight.bold)),
        ),
      ],
    ),
  );
}

void showPremiumRequiredDialog(BuildContext context) {
  showDialog(
    context: context,
    builder: (ctx) => AlertDialog(
      backgroundColor: const Color(0xFF151515),
      shape: RoundedRectangleBorder(
        side: const BorderSide(color: Colors.lightBlueAccent, width: 1.5),
        borderRadius: BorderRadius.circular(12),
      ),
      title: GestureDetector(
        onLongPress: () => _showCryptoVaultTesterUnlock(context),
        child: const Row(
          children: [
            Text('💎', style: TextStyle(fontSize: 22)),
            SizedBox(width: 10),
            Text('PREMIUM REQUIRED', style: TextStyle(color: Colors.lightBlueAccent, fontWeight: FontWeight.bold, fontSize: 14)),
          ],
        ),
      ),
      content: const Text(
        'Store all your cryptocurrencies in a military-grade local vault. Send funds to anyone and receive from anywhere, with zero middlemen and absolute privacy.\n\n'
        'Unlocking the Web3 Crypto Vault requires a Premium subscription.',
        style: TextStyle(color: Colors.white70, height: 1.4, fontSize: 13),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(ctx),
          child: const Text('CLOSE', style: TextStyle(color: Colors.grey)),
        ),
        TextButton(
          onPressed: () async {
            Navigator.pop(ctx);
            try {
              await PremiumService.buy(PremiumService.monthlyProductId);
            } catch (e) {
              if (context.mounted) {
                ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('$e')));
              }
            }
          },
          child: const Text('MONTHLY', style: TextStyle(color: Colors.amber, fontWeight: FontWeight.bold)),
        ),
        TextButton(
          onPressed: () async {
            Navigator.pop(ctx);
            try {
              await PremiumService.buy(PremiumService.yearlyProductId);
            } catch (e) {
              if (context.mounted) {
                ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('$e')));
              }
            }
          },
          child: const Text('YEARLY', style: TextStyle(color: Colors.amber, fontWeight: FontWeight.bold)),
        ),
      ],
    ),
  );
}

  Future<void> showNotification(String title, String body) async {
  // "Silent Mode" e "Push Notifications" são a mesma coisa vista de dois
  // lados - uma única definição gravada no cofre, lida aqui antes de
  // mostrar qualquer aviso local.
  final notificationsEnabled = Hive.box('padlock_vault').get('notifications_enabled', defaultValue: true);
  if (notificationsEnabled == false) return;
  const AndroidNotificationDetails androidDetails = AndroidNotificationDetails(
    'padlock_secure_channel', 'Secure Notifications',
    importance: Importance.max, priority: Priority.high,
  );
  await flutterLocalNotificationsPlugin.show(0, title, body, const NotificationDetails(android: androidDetails));
}
Future<String> computeSafetyNumber(String pubKeyA, String pubKeyB) async {
  final sorted = [pubKeyA, pubKeyB]..sort();
  final combined = utf8.encode(sorted.join());
  final digest = await crypto.Sha256().hash(combined);
  final hex = digest.bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  final digitsBig = BigInt.parse(hex, radix: 16).toString().padLeft(60, '0');
  final digits = digitsBig.substring(digitsBig.length - 60);
  final groups = <String>[];
  for (int i = 0; i < digits.length; i += 5) {
    groups.add(digits.substring(i, i + 5));
  }
  return groups.join(' ');
}