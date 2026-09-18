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
  // Última lista de servidores ICE (STUN+TURN) que o servidor confirmou -
  // serve de rede de segurança se um pedido futuro demorar demasiado numa
  // ligação de dados móveis mais lenta: melhor reutilizar TURN recente do
  // que cair para STUN sozinho, que não atravessa duas redes móveis com
  // NAT restritivo (a causa mais provável de "dados móveis com dados
  // móveis" nunca sair de "Exchanging Encryption Keys").
  static List<Map<String, dynamic>>? cachedIceServers;

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
  // Tranca por contacto - garante que nextSendKey/receiveMessageKey nunca
  // correm ao mesmo tempo para o MESMO peerId. Sem isto, duas mensagens a
  // chegar perto uma da outra (muito provável logo após reconectar, quando
  // o servidor entrega várias mensagens em fila de uma vez) podiam ler o
  // mesmo estado da cadeia em simultâneo e escrever de volta em cima uma da
  // outra - um Double Ratchet corrompido desta forma NUNCA se cura sozinho
  // (é precisamente "sigilo perante o futuro": não há como recuar), o que
  // bate certo com "todas as mensagens ficam para sempre por decifrar depois
  // de um problema de rede, nunca recupera".
  static final Map<String, Future<dynamic>> _locks = {};

  static Future<T> _withLock<T>(String peerId, Future<T> Function() action) {
    final previous = _locks[peerId] ?? Future<void>.value();
    final result = previous.then((_) => action());
    // Guarda a nova promessa já "protegida" contra erros, para uma
    // mensagem que falhe a decifrar não travar as seguintes na fila.
    _locks[peerId] = result.then((_) {}, onError: (_) {});
    return result;
  }

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

  static Future<Map<String, dynamic>> nextSendKey(String peerId) {
    return _withLock(peerId, () => _nextSendKeyLocked(peerId));
  }

  static Future<Map<String, dynamic>> _nextSendKeyLocked(String peerId) async {
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
  static Future<Uint8List?> receiveMessageKey(String peerId, int targetIndex, {String? theirDhPub}) {
    return _withLock(peerId, () => _receiveMessageKeyLocked(peerId, targetIndex, theirDhPub: theirDhPub));
  }

  static Future<Uint8List?> _receiveMessageKeyLocked(String peerId, int targetIndex, {String? theirDhPub}) async {
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

      } else if (event.event == Event.actionCallTimeout) {
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
  // O idioma escolhido tem de sobreviver a fechar a app - antes só durava
  // enquanto a app ficava aberta, voltando sempre a inglês ao reabrir.
  // Lido via SharedPreferences (não o cofre Hive) porque tem de estar
  // disponível mesmo antes do login/PIN.
  final savedLanguage = (await SharedPreferences.getInstance()).getString('app_language') ?? 'EN';
  runApp(PadlockApp(isFirstTime: isFirstTime, initialLanguage: savedLanguage));
}

class PadlockApp extends StatefulWidget {
  final bool isFirstTime;
  final String initialLanguage;

  const PadlockApp({super.key, required this.isFirstTime, this.initialLanguage = 'EN'});

  @override
  State<PadlockApp> createState() => _PadlockAppState();
}

class _PadlockAppState extends State<PadlockApp> with WidgetsBindingObserver {
  late String _currentLanguage;

  @override
  void initState() {
    super.initState();
    _currentLanguage = widget.initialLanguage;
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
    SharedPreferences.getInstance().then((prefs) => prefs.setString('app_language', lang));
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
    'language': 'Language',
    'search_contact_hint': 'Search contact...',
    'encrypted_p2p_contact': 'Encrypted P2P Contact',
    'encrypted_p2p_message_preview': '[Encrypted P2P Message]',
    'delete_chat_confirm_title': 'Delete Chat',
    'delete_chat_confirm_body': 'Do you want to permanently delete this chat?',
    'cancel_button': 'Cancel',
    'delete_button': 'Delete',
    'settings_header': 'SETTINGS',
    'section_core_security': 'Core Security Protocols',
    'info_encryption_title': 'Military-Grade Encryption',
    'info_encryption_desc': 'AES-256-GCM and Curve25519 standard.',
    'info_p2p_title': 'True Peer-to-Peer',
    'info_p2p_desc': 'Direct voice & data. Zero server routing.',
    'info_autodestruct_title': 'Forensic Auto-Destruct',
    'info_autodestruct_desc': 'All messages shred within 24 hours max.',
    'info_screenshot_title': 'Screenshot Protection',
    'info_screenshot_desc': 'Screen capture is globally blocked across the app to prevent unauthorized data leaks.',
    'info_timeout_title': 'Safe Timeout',
    'info_timeout_desc': 'App closes automatically after 15 minutes of use for your security. Login is required to resume. Active calls bypass this rule to maintain connection.',
    'section_premium': 'Padlock Premium',
    'secure_crypto_vault_title': 'Secure Crypto Vault',
    'crypto_vault_desc': 'Maximum security storage for your digital assets.',
    'section_help_center': 'Help Center / How to Use',
    'help_vault_files_q': 'How to use Secure Vault Files?',
    'help_vault_files_a': 'To access this section, you must create a dedicated encrypted key. Whenever you open the vault, it will prompt you for this key to log in, working just like the app security login.\n\n• All photos taken directly within Padlock are saved here automatically.\n• Documents and photos sent by contacts to your ID are routed directly to this vault instead of normal chats. You will receive a notification alert that media was sent, and you must access it inside the vault to view.\n• Files remain 100% encrypted and secure until manually deleted, exported, or re-sent.',
    'help_add_contact_q': 'How to add a contact?',
    'help_add_contact_a': 'Go to the "Contacts" tab, tap the blue (+) button, and either paste a Privacy ID or use the green QR scanner.',
    'help_share_id_q': 'How to share my ID?',
    'help_share_id_a': 'Go to the "Profile" tab. Tap "Copy ID" to paste it securely anywhere, or "QR Code" to let someone scan your screen.',
    'help_rename_contact_q': 'How to rename a contact?',
    'help_rename_contact_a': 'In the "Contacts" tab, tap the Edit (pencil) icon next to any contact to change their display name.',
    'help_delete_contact_q': 'How to delete a contact?',
    'help_delete_contact_a': 'In the "Contacts" tab, long-press on any contact. This will permanently delete them and shred the shared encryption keys.',
    'help_wipe_chat_q': 'How to wipe a conversation?',
    'help_wipe_chat_a': 'Inside any active chat, tap the menu (three dots) in the top right corner and select "Wipe Conversation" to obliterate all messages on both devices.',
    'section_app_preferences': 'App Preferences',
    'app_language_title': 'App Language',
    'current_lang_prefix': 'Current',
    'silent_mode_desc': 'Mutes all notifications and call ringtones.',
    'section_panic_room': 'Panic Room',
    'nuke_vault_title': 'NUKE VAULT: PURGE & DESTROY EVERYTHING',
    'nuke_vault_desc': 'This action will permanently shred your Privacy ID, crypto funds, and all chats. It clears everything and sends you back to the activation screen.',
    'critical_warning_title': 'CRITICAL WARNING',
    'nuke_confirm_body': 'Are you sure you want to NUKE the vault?\n\n⚠️ WITHDRAW ALL CRYPTO FUNDS AND SAVE YOUR FILES BEFORE PROCEEDING.\n\nThis action is irreversible. The application will be wiped to a factory state.',
    'nuke_everything_button': 'NUKE EVERYTHING',
    'got_it_button': 'Got it',
    'edit_name_title': 'Edit Name',
    'save_button': 'Save',
    'qr_code_button': 'QR Code',
    'copy_id_button': 'Copy ID',
    'secure_crypto_vault_short': 'Secure\nCrypto Vault',
    'secure_vault_files_short': 'Secure\nVault Files',
    'privacy_id_label': 'Privacy ID',
    'profile_bio_paragraph': 'Engineered with military-grade Zero-Knowledge encryption.\nAll communications operate strictly Peer-to-Peer (P2P).\nMessages automatically self-destruct after 24 hours\nusing secure anti-trace memory sanitization.\nZero trace, zero logs, total privacy.',
    'close_button': 'Close',
    'crypto_code_too_weak': 'Code is too weak: use at least 10 characters and avoid repeated or sequential patterns.',
    'invalid_recovery_phrase': 'Invalid recovery phrase - check the words and try again.',
    'crypto_vault_not_initialized': 'Crypto Vault not initialized on this device.',
    'invalid_crypto_vault_code': 'Invalid Crypto Vault code.',
    'crypto_vault_corrupted': 'Crypto Vault data is corrupted (code was correct, but the vault file itself is damaged).',
    'create_crypto_vault_code_title': 'CREATE CRYPTO VAULT CODE',
    'enter_crypto_vault_code_title': 'ENTER CRYPTO VAULT CODE',
    'crypto_code_desc_create': 'This code is separate from your app and Vault Files codes. It protects a brand-new, non-custodial wallet that only you control.',
    'crypto_code_desc_enter': 'Enter your Crypto Vault code to access your wallet.',
    'create_new_wallet_instead': '← Create a new wallet instead',
    'already_have_recovery_phrase': 'I already have a recovery phrase (lost phone / reinstall)',
    'recovery_phrase_label': 'Your 12-word recovery phrase',
    'recovery_phrase_hint': 'word1 word2 word3 ...',
    'set_crypto_vault_code_label': 'Set Crypto Vault Code (for THIS device)',
    'crypto_vault_code_label': 'Crypto Vault Code',
    'restore_wallet_button': 'RESTORE WALLET',
    'create_wallet_button': 'CREATE WALLET',
    'unlock_button': 'UNLOCK',
    'recovery_phrase_title': 'Your Recovery Phrase',
    'recovery_phrase_warning': '⚠️ Write these 12 words down on paper, in order, and keep them somewhere safe and offline. Anyone with these words can steal your funds. Padlock does NOT store this phrase anywhere and cannot recover it for you.',
    'recovery_phrase_confirm_checkbox': 'I have written down these words and stored them safely offline.',
    'continue_button': 'CONTINUE',
    'loading_text': 'Loading...',
    'could_not_load_balance': 'Could not load balance',
    'receive_dialog_title': 'Receive',
    'receive_address_warning': 'Scanning or sharing this code gives out your wallet ADDRESS only - never your recovery phrase.',
    'address_copied_toast': 'Address copied.',
    'copy_button': 'COPY',
    'testnet_warning': '⚠️ TESTNET (Polygon Amoy) - these are NOT real funds.',
    'balances_label': 'Balances',
    'receive_button': 'RECEIVE',
    'send_button': 'SEND',
    'camera_permission_denied': 'Camera permission denied. Enable it in phone Settings > Apps > Padlock > Permissions.',
    'scan_wallet_address_title': 'Scan Wallet Address',
    'invalid_wallet_address': 'Invalid wallet address.',
    'enter_valid_amount': 'Enter a valid amount.',
    'price_not_loaded': 'Price not loaded yet - try again in a moment.',
    'transaction_sent_title': 'Transaction Sent',
    'done_button': 'DONE',
    'send_failed_prefix': 'Send failed',
    'send_title': 'Send',
    'recipient_address_label': 'Recipient wallet address',
    'coin_label': 'Coin',
    'amount_in_label': 'Amount in:',
    'amount_usd_label': 'Amount (USD)',
    'amount_label_prefix': 'Amount',
    'loading_price': 'Loading price...',
    'price_label_prefix': 'Price',
    'confirm_send_button': 'CONFIRM & SEND',
    'vault_files_not_initialized': 'Vault Files not initialized on this device.',
    'invalid_vault_files_code': 'Invalid Vault Files code.',
    'vault_files_corrupted': 'Vault Files data is corrupted (code was correct, but the vault file itself is damaged).',
    'create_vault_files_code_title': 'CREATE VAULT FILES CODE',
    'enter_vault_files_code_title': 'ENTER VAULT FILES CODE',
    'vault_files_code_desc_create': 'This code is separate from your app unlock code. Anyone who knows your app code will NOT be able to open your photos and documents without it too.',
    'vault_files_code_desc_enter': 'Enter your Vault Files code to view your encrypted photos and documents.',
    'set_vault_files_code_label': 'Set Vault Files Code',
    'vault_files_code_label': 'Vault Files Code',
    'create_vault_button': 'CREATE VAULT',
    'imported_skipped_toast': '{imported} imported, {skipped} skipped (max {mb}MB each).',
    'no_contacts_yet': 'No contacts yet.',
    'send_to_title': 'Send to...',
    'sent_toast': 'Sent.',
    'failed_to_send_prefix': 'Failed to send',
    'received_from_prefix': 'Received from',
    'sent_to_prefix': 'Sent to',
    'stored_locally_not_sent': 'Stored locally — not sent to anyone yet',
    'document_label': 'Document',
    'document_stored_encrypted_desc': 'This document is stored encrypted in your Vault Files ({kb} KB). Use Export to save it back to your phone or share it.',
    'export_button': 'Export',
    'personal_files_empty': 'No personal files yet.\nUse the + button to take a photo or import a document.',
    'received_files_empty': 'Nothing received yet.',
    'sent_files_empty': 'Nothing sent yet.',
    'tab_personal': 'Personal',
    'tab_received': 'Received',
    'tab_sent': 'Sent',
    'copy_message': 'Copy Message',
    'destroy_message': 'Destroy Message',
    'node_destruction_title': 'Node Destruction',
    'destroy_message_confirm_body': 'Do you want to permanently destroy this message on both devices?',
    'destroy_button': 'Destroy',
    'failed_to_send_photo_prefix': 'Failed to send photo',
    'encrypted_photo_sent_message': '🖼️ Encrypted photo sent — view in Secure Vault Files',
    'photo_chat_preview': '🖼️ Photo',
    'just_now': 'Just Now',
    'failed_to_send_voice_prefix': 'Failed to send voice message',
    'voice_message_chat_preview': '🎤 Voice message',
    'voice_message_label': 'Voice message',
    'no_secure_channel_error': 'Could not send: no secure channel with this contact yet ({error}). Try removing and re-adding them.',
    'block_id_title': 'Block ID',
    'block_id_confirm_body': 'Do you want to permanently block this ID?',
    'block_button': 'Block',
    'keys_not_available': 'Keys not available for this contact.',
    'safety_number_title': 'Safety Number',
    'safety_number_desc': 'Make a secure call to this contact and read this number aloud. If they match on both devices, nobody is intercepting your conversation.',
    'verify_safety_number': 'Verify Safety Number',
    'encrypted_p2p_channel': 'Encrypted P2P Channel',
    'destruct_1m': '1 Minute',
    'destruct_5m': '5 Minutes',
    'destruct_1h': '1 Hour',
    'destruct_24h': '24 Hours',
    'message_not_decrypted': '[Message not decrypted]',
    'call_status_connecting': 'Connecting...',
    'call_status_exchanging_keys': 'Exchanging Encryption Keys...',
    'call_status_ringing': 'Ringing...',
    'call_status_connecting_encrypted': 'Connecting Encrypted Call...',
    'call_status_incoming_encrypted': 'Incoming Encrypted Call...',
    'call_status_connected_prefix': 'Connected',
    'call_status_connected_encrypted': 'Connected and Encrypted',
    'call_status_reconnecting': 'Reconnecting...',
    'call_contact_unavailable': 'Contact Unavailable or Offline.',
    'missed_secure_call': 'Missed Secure Call',
    'missed_call_notification_title': 'Missed Call',
    'setup_code_too_weak': 'Decryption Key is too weak: use at least 10 characters and avoid repeated or sequential patterns.',
    'vault_init_failed_prefix': 'Vault initialization failed',
    'create_vault_title': 'CREATE YOUR ENCRYPTED VAULT',
    'create_vault_subtitle': 'Set your master key to generate\nP2P cryptographic identity',
    'set_decryption_key_label': 'Set Decryption Key',
    'strength_too_weak': 'Too weak',
    'strength_weak': 'Weak',
    'strength_medium': 'Medium',
    'strength_strong': 'Strong',
    'strength_very_strong': 'Very strong',
    'initialize_vault_button': 'INITIALIZE VAULT',
    'footer_privacy_text': 'Engineered with military-grade Zero-Knowledge encryption.\nAll communications operate strictly Peer-to-Peer (P2P).\nMessages automatically self-destruct after 24 hours\nusing secure anti-trace memory sanitization.\nZero trace, zero logs, total privacy.',
    'vault_not_initialized_device': 'Vault not initialized on this device.',
    'invalid_decryption_key': 'Invalid Decryption Key.',
    'vault_data_corrupted': 'Vault data is corrupted (key was correct, but the vault file itself is damaged).',
    'decrypt_padlock_title': 'DECRYPT YOUR PADLOCK',
    'login_subtitle': 'ENGINEERED WITH MILITARY-GRADE\nZERO-KNOWLEDGE ENCRYPTION',
    'enter_decryption_key_label': 'Enter Decryption Key',
    'access_vault_button': 'ACCESS VAULT',
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
    'language': 'Idioma',
    'search_contact_hint': 'Pesquisar contacto...',
    'encrypted_p2p_contact': 'Contacto P2P Encriptado',
    'encrypted_p2p_message_preview': '[Mensagem P2P Encriptada]',
    'delete_chat_confirm_title': 'Apagar Conversa',
    'delete_chat_confirm_body': 'Queres apagar esta conversa permanentemente?',
    'cancel_button': 'Cancelar',
    'delete_button': 'Apagar',
    'settings_header': 'DEFINIÇÕES',
    'section_core_security': 'Protocolos de Segurança Principais',
    'info_encryption_title': 'Encriptação de Nível Militar',
    'info_encryption_desc': 'Padrão AES-256-GCM e Curve25519.',
    'info_p2p_title': 'Verdadeiro Peer-to-Peer',
    'info_p2p_desc': 'Voz e dados diretos. Zero encaminhamento por servidor.',
    'info_autodestruct_title': 'Auto-Destruição Forense',
    'info_autodestruct_desc': 'Todas as mensagens são destruídas em, no máximo, 24 horas.',
    'info_screenshot_title': 'Proteção Contra Capturas de Ecrã',
    'info_screenshot_desc': 'A captura de ecrã é bloqueada globalmente em toda a app para evitar fugas de dados não autorizadas.',
    'info_timeout_title': 'Fecho Automático Seguro',
    'info_timeout_desc': 'A app fecha automaticamente após 15 minutos de uso, para tua segurança. É preciso fazer login novamente para continuar. Chamadas ativas ignoram esta regra para manter a ligação.',
    'section_premium': 'Padlock Premium',
    'secure_crypto_vault_title': 'Secure Crypto Vault',
    'crypto_vault_desc': 'Armazenamento de máxima segurança para os teus ativos digitais.',
    'section_help_center': 'Centro de Ajuda / Como Usar',
    'help_vault_files_q': 'Como usar o Secure Vault Files?',
    'help_vault_files_a': 'Para aceder a esta secção, tens de criar um código encriptado próprio. Sempre que abrires o cofre, ele vai pedir-te esse código para entrares, tal como o login de segurança da app.\n\n• Todas as fotos tiradas diretamente dentro da Padlock são guardadas aqui automaticamente.\n• Documentos e fotos enviados por contactos para o teu ID vão diretamente para este cofre em vez das conversas normais. Vais receber um aviso a dizer que foi enviado conteúdo, e tens de aceder ao cofre para o ver.\n• Os ficheiros mantêm-se 100% encriptados e seguros até serem apagados, exportados ou reenviados manualmente.',
    'help_add_contact_q': 'Como adicionar um contacto?',
    'help_add_contact_a': 'Vai ao separador "Contactos", toca no botão azul (+), e cola um ID de Privacidade ou usa o scanner de QR verde.',
    'help_share_id_q': 'Como partilhar o meu ID?',
    'help_share_id_a': 'Vai ao separador "Perfil". Toca em "Copy ID" para o colares em qualquer lado com segurança, ou em "QR Code" para alguém digitalizar o teu ecrã.',
    'help_rename_contact_q': 'Como renomear um contacto?',
    'help_rename_contact_a': 'No separador "Contactos", toca no ícone de Editar (lápis) ao lado de qualquer contacto para mudar o nome que aparece.',
    'help_delete_contact_q': 'Como apagar um contacto?',
    'help_delete_contact_a': 'No separador "Contactos", mantém o dedo pressionado sobre qualquer contacto. Isto apaga-o permanentemente e destrói as chaves de encriptação partilhadas.',
    'help_wipe_chat_q': 'Como apagar uma conversa?',
    'help_wipe_chat_a': 'Dentro de qualquer conversa ativa, toca no menu (três pontinhos) no canto superior direito e escolhe "Apagar Conversa" para destruir todas as mensagens em ambos os telemóveis.',
    'section_app_preferences': 'Preferências da App',
    'app_language_title': 'Idioma da App',
    'current_lang_prefix': 'Atual',
    'silent_mode_desc': 'Silencia todas as notificações e toques de chamada.',
    'section_panic_room': 'Sala de Pânico',
    'nuke_vault_title': 'DESTRUIR COFRE: PURGAR E DESTRUIR TUDO',
    'nuke_vault_desc': 'Esta ação destrói permanentemente o teu ID de Privacidade, fundos de cripto, e todas as conversas. Limpa tudo e devolve-te ao ecrã de ativação.',
    'critical_warning_title': 'AVISO CRÍTICO',
    'nuke_confirm_body': 'Tens a certeza que queres DESTRUIR o cofre?\n\n⚠️ LEVANTA TODOS OS FUNDOS DE CRIPTO E GUARDA OS TEUS FICHEIROS ANTES DE CONTINUAR.\n\nEsta ação é irreversível. A aplicação vai ficar como se tivesse acabado de ser instalada.',
    'nuke_everything_button': 'DESTRUIR TUDO',
    'got_it_button': 'Entendido',
    'edit_name_title': 'Editar Nome',
    'save_button': 'Guardar',
    'qr_code_button': 'Código QR',
    'copy_id_button': 'Copiar ID',
    'secure_crypto_vault_short': 'Secure\nCrypto Vault',
    'secure_vault_files_short': 'Secure\nVault Files',
    'privacy_id_label': 'ID de Privacidade',
    'profile_bio_paragraph': 'Construído com encriptação de Conhecimento-Zero de nível militar.\nTodas as comunicações funcionam estritamente Peer-to-Peer (P2P).\nAs mensagens autodestroem-se automaticamente ao fim de 24 horas\nusando sanitização de memória anti-rasto segura.\nZero rasto, zero registos, privacidade total.',
    'close_button': 'Fechar',
    'crypto_code_too_weak': 'O código é fraco demais: usa pelo menos 10 caracteres e evita padrões repetidos ou sequenciais.',
    'invalid_recovery_phrase': 'Frase de recuperação inválida - verifica as palavras e tenta novamente.',
    'crypto_vault_not_initialized': 'Crypto Vault não inicializado neste dispositivo.',
    'invalid_crypto_vault_code': 'Código do Crypto Vault inválido.',
    'crypto_vault_corrupted': 'Os dados do Crypto Vault estão corrompidos (o código estava certo, mas o próprio ficheiro do cofre está danificado).',
    'create_crypto_vault_code_title': 'CRIAR CÓDIGO DO CRYPTO VAULT',
    'enter_crypto_vault_code_title': 'INTRODUZIR CÓDIGO DO CRYPTO VAULT',
    'crypto_code_desc_create': 'Este código é separado dos códigos da app e do Vault Files. Protege uma carteira nova, não-custodial, que só tu controlas.',
    'crypto_code_desc_enter': 'Introduz o teu código do Crypto Vault para aceder à tua carteira.',
    'create_new_wallet_instead': '← Criar uma carteira nova em vez disso',
    'already_have_recovery_phrase': 'Já tenho uma frase de recuperação (perdi o telemóvel / reinstalei)',
    'recovery_phrase_label': 'A tua frase de recuperação de 12 palavras',
    'recovery_phrase_hint': 'palavra1 palavra2 palavra3 ...',
    'set_crypto_vault_code_label': 'Definir Código do Crypto Vault (para ESTE dispositivo)',
    'crypto_vault_code_label': 'Código do Crypto Vault',
    'restore_wallet_button': 'RESTAURAR CARTEIRA',
    'create_wallet_button': 'CRIAR CARTEIRA',
    'unlock_button': 'DESBLOQUEAR',
    'recovery_phrase_title': 'A Tua Frase de Recuperação',
    'recovery_phrase_warning': '⚠️ Escreve estas 12 palavras em papel, pela ordem certa, e guarda-as num sítio seguro e offline. Quem tiver estas palavras pode roubar os teus fundos. A Padlock NÃO guarda esta frase em lado nenhum e não a consegue recuperar por ti.',
    'recovery_phrase_confirm_checkbox': 'Já escrevi estas palavras e guardei-as em segurança offline.',
    'continue_button': 'CONTINUAR',
    'loading_text': 'A carregar...',
    'could_not_load_balance': 'Não foi possível carregar o saldo',
    'receive_dialog_title': 'Receber',
    'receive_address_warning': 'Digitalizar ou partilhar este código só dá o ENDEREÇO da tua carteira - nunca a tua frase de recuperação.',
    'address_copied_toast': 'Endereço copiado.',
    'copy_button': 'COPIAR',
    'testnet_warning': '⚠️ REDE DE TESTE (Polygon Amoy) - isto NÃO são fundos reais.',
    'balances_label': 'Saldos',
    'receive_button': 'RECEBER',
    'send_button': 'ENVIAR',
    'camera_permission_denied': 'Permissão da câmara negada. Ativa-a em Definições do telemóvel > Apps > Padlock > Permissões.',
    'scan_wallet_address_title': 'Digitalizar Endereço de Carteira',
    'invalid_wallet_address': 'Endereço de carteira inválido.',
    'enter_valid_amount': 'Introduz um montante válido.',
    'price_not_loaded': 'A cotação ainda não carregou - tenta novamente daqui a pouco.',
    'transaction_sent_title': 'Transação Enviada',
    'done_button': 'CONCLUÍDO',
    'send_failed_prefix': 'Falha ao enviar',
    'send_title': 'Enviar',
    'recipient_address_label': 'Endereço da carteira do destinatário',
    'coin_label': 'Moeda',
    'amount_in_label': 'Montante em:',
    'amount_usd_label': 'Montante (USD)',
    'amount_label_prefix': 'Montante',
    'loading_price': 'A carregar cotação...',
    'price_label_prefix': 'Cotação',
    'confirm_send_button': 'CONFIRMAR E ENVIAR',
    'vault_files_not_initialized': 'O Secure Vault Files não está inicializado neste dispositivo.',
    'invalid_vault_files_code': 'Código do Secure Vault Files inválido.',
    'vault_files_corrupted': 'Os dados do Secure Vault Files estão corrompidos (o código estava correto, mas o próprio ficheiro do cofre está danificado).',
    'create_vault_files_code_title': 'CRIAR CÓDIGO DO VAULT FILES',
    'enter_vault_files_code_title': 'INTRODUZIR CÓDIGO DO VAULT FILES',
    'vault_files_code_desc_create': 'Este código é diferente do código de desbloqueio da app. Quem souber o código da app NÃO conseguirá abrir as tuas fotos e documentos sem este também.',
    'vault_files_code_desc_enter': 'Introduz o teu código do Vault Files para veres as tuas fotos e documentos encriptados.',
    'set_vault_files_code_label': 'Definir Código do Vault Files',
    'vault_files_code_label': 'Código do Vault Files',
    'create_vault_button': 'CRIAR COFRE',
    'imported_skipped_toast': '{imported} importados, {skipped} ignorados (máx. {mb}MB cada).',
    'no_contacts_yet': 'Ainda não tens contactos.',
    'send_to_title': 'Enviar para...',
    'sent_toast': 'Enviado.',
    'failed_to_send_prefix': 'Falha ao enviar',
    'received_from_prefix': 'Recebido de',
    'sent_to_prefix': 'Enviado para',
    'stored_locally_not_sent': 'Guardado localmente — ainda não enviado a ninguém',
    'document_label': 'Documento',
    'document_stored_encrypted_desc': 'Este documento está guardado encriptado no teu Vault Files ({kb} KB). Usa Exportar para o guardares de novo no telemóvel ou partilhares.',
    'export_button': 'Exportar',
    'personal_files_empty': 'Ainda não tens ficheiros pessoais.\nUsa o botão + para tirar uma foto ou importar um documento.',
    'received_files_empty': 'Ainda não recebeste nada.',
    'sent_files_empty': 'Ainda não enviaste nada.',
    'tab_personal': 'Pessoal',
    'tab_received': 'Recebidos',
    'tab_sent': 'Enviados',
    'copy_message': 'Copiar Mensagem',
    'destroy_message': 'Destruir Mensagem',
    'node_destruction_title': 'Destruição de Nó',
    'destroy_message_confirm_body': 'Deseja destruir esta mensagem permanentemente em ambos os dispositivos?',
    'destroy_button': 'Destruir',
    'failed_to_send_photo_prefix': 'Falha ao enviar foto',
    'encrypted_photo_sent_message': '🖼️ Foto encriptada enviada — vê no Secure Vault Files',
    'photo_chat_preview': '🖼️ Foto',
    'just_now': 'Agora Mesmo',
    'failed_to_send_voice_prefix': 'Falha ao enviar mensagem de voz',
    'voice_message_chat_preview': '🎤 Mensagem de voz',
    'voice_message_label': 'Mensagem de voz',
    'no_secure_channel_error': 'Não foi possível enviar: ainda não há canal seguro com este contacto ({error}). Tenta remover e adicionar novamente.',
    'block_id_title': 'Bloquear ID',
    'block_id_confirm_body': 'Deseja bloquear permanentemente este ID?',
    'block_button': 'Bloquear',
    'keys_not_available': 'Chaves não disponíveis para este contacto.',
    'safety_number_title': 'Número de Segurança',
    'safety_number_desc': 'Faz uma chamada segura a este contacto e lê este número em voz alta. Se coincidir nos dois dispositivos, ninguém está a intercetar a tua conversa.',
    'verify_safety_number': 'Verificar Número de Segurança',
    'encrypted_p2p_channel': 'Canal P2P Encriptado',
    'destruct_1m': '1 Minuto',
    'destruct_5m': '5 Minutos',
    'destruct_1h': '1 Hora',
    'destruct_24h': '24 Horas',
    'message_not_decrypted': '[Mensagem não decifrada]',
    'call_status_connecting': 'A ligar...',
    'call_status_exchanging_keys': 'A trocar chaves de encriptação...',
    'call_status_ringing': 'A tocar...',
    'call_status_connecting_encrypted': 'A ligar chamada encriptada...',
    'call_status_incoming_encrypted': 'Chamada encriptada a receber...',
    'call_status_connected_prefix': 'Ligado',
    'call_status_connected_encrypted': 'Ligado e encriptado',
    'call_status_reconnecting': 'A religar...',
    'call_contact_unavailable': 'Contacto indisponível ou offline.',
    'missed_secure_call': 'Chamada Segura Perdida',
    'missed_call_notification_title': 'Chamada Perdida',
    'setup_code_too_weak': 'A chave de encriptação é demasiado fraca: usa pelo menos 10 caracteres e evita padrões repetidos ou sequenciais.',
    'vault_init_failed_prefix': 'Falha ao inicializar o cofre',
    'create_vault_title': 'CRIA O TEU COFRE ENCRIPTADO',
    'create_vault_subtitle': 'Define a tua chave-mestra para gerar\na identidade criptográfica P2P',
    'set_decryption_key_label': 'Definir Chave de Encriptação',
    'strength_too_weak': 'Demasiado fraca',
    'strength_weak': 'Fraca',
    'strength_medium': 'Média',
    'strength_strong': 'Forte',
    'strength_very_strong': 'Muito forte',
    'initialize_vault_button': 'INICIALIZAR COFRE',
    'footer_privacy_text': 'Desenvolvido com encriptação Zero-Knowledge de nível militar.\nTodas as comunicações operam estritamente Peer-to-Peer (P2P).\nAs mensagens autodestroem-se automaticamente após 24 horas\nusando sanitização segura de memória anti-vestígios.\nZero vestígios, zero registos, privacidade total.',
    'vault_not_initialized_device': 'Cofre não inicializado neste dispositivo.',
    'invalid_decryption_key': 'Chave de Encriptação inválida.',
    'vault_data_corrupted': 'Os dados do cofre estão corrompidos (a chave estava correta, mas o próprio ficheiro do cofre está danificado).',
    'decrypt_padlock_title': 'DECIFRA O TEU PADLOCK',
    'login_subtitle': 'DESENVOLVIDO COM ENCRIPTAÇÃO\nZERO-KNOWLEDGE DE NÍVEL MILITAR',
    'enter_decryption_key_label': 'Introduzir Chave de Encriptação',
    'access_vault_button': 'ACEDER AO COFRE',
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
    'language': 'Idioma',
    'search_contact_hint': 'Buscar contacto...',
    'encrypted_p2p_contact': 'Contacto P2P Encriptado',
    'encrypted_p2p_message_preview': '[Mensaje P2P Encriptado]',
    'delete_chat_confirm_title': 'Eliminar Conversación',
    'delete_chat_confirm_body': '¿Quieres eliminar esta conversación permanentemente?',
    'cancel_button': 'Cancelar',
    'delete_button': 'Eliminar',
    'settings_header': 'AJUSTES',
    'section_core_security': 'Protocolos de Seguridad Principales',
    'info_encryption_title': 'Encriptación de Nivel Militar',
    'info_encryption_desc': 'Estándar AES-256-GCM y Curve25519.',
    'info_p2p_title': 'Verdadero Peer-to-Peer',
    'info_p2p_desc': 'Voz y datos directos. Cero enrutamiento por servidor.',
    'info_autodestruct_title': 'Autodestrucción Forense',
    'info_autodestruct_desc': 'Todos los mensajes se destruyen en un máximo de 24 horas.',
    'info_screenshot_title': 'Protección de Capturas de Pantalla',
    'info_screenshot_desc': 'La captura de pantalla está bloqueada globalmente en toda la app para evitar fugas de datos no autorizadas.',
    'info_timeout_title': 'Cierre Automático Seguro',
    'info_timeout_desc': 'La app se cierra automáticamente tras 15 minutos de uso, por tu seguridad. Es necesario iniciar sesión de nuevo para continuar. Las llamadas activas ignoran esta regla para mantener la conexión.',
    'section_premium': 'Padlock Premium',
    'secure_crypto_vault_title': 'Secure Crypto Vault',
    'crypto_vault_desc': 'Almacenamiento de máxima seguridad para tus activos digitales.',
    'section_help_center': 'Centro de Ayuda / Cómo Usar',
    'help_vault_files_q': '¿Cómo usar Secure Vault Files?',
    'help_vault_files_a': 'Para acceder a esta sección, debes crear una clave encriptada dedicada. Cada vez que abras la bóveda, te pedirá esta clave para entrar, igual que el inicio de sesión de seguridad de la app.\n\n• Todas las fotos tomadas directamente dentro de Padlock se guardan aquí automáticamente.\n• Los documentos y fotos enviados por contactos a tu ID se dirigen directamente a esta bóveda en lugar de a los chats normales. Recibirás una alerta de que se envió contenido, y debes acceder a la bóveda para verlo.\n• Los archivos permanecen 100% encriptados y seguros hasta que se eliminen, exporten o reenvíen manualmente.',
    'help_add_contact_q': '¿Cómo agregar un contacto?',
    'help_add_contact_a': 'Ve a la pestaña "Contactos", toca el botón azul (+), y pega un ID de Privacidad o usa el escáner de QR verde.',
    'help_share_id_q': '¿Cómo compartir mi ID?',
    'help_share_id_a': 'Ve a la pestaña "Perfil". Toca "Copy ID" para pegarlo de forma segura en cualquier lugar, o "QR Code" para que alguien escanee tu pantalla.',
    'help_rename_contact_q': '¿Cómo renombrar un contacto?',
    'help_rename_contact_a': 'En la pestaña "Contactos", toca el icono de Editar (lápiz) junto a cualquier contacto para cambiar su nombre visible.',
    'help_delete_contact_q': '¿Cómo eliminar un contacto?',
    'help_delete_contact_a': 'En la pestaña "Contactos", mantén pulsado cualquier contacto. Esto lo eliminará permanentemente y destruirá las claves de encriptación compartidas.',
    'help_wipe_chat_q': '¿Cómo borrar una conversación?',
    'help_wipe_chat_a': 'Dentro de cualquier chat activo, toca el menú (tres puntos) en la esquina superior derecha y selecciona "Borrar Conversación" para destruir todos los mensajes en ambos dispositivos.',
    'section_app_preferences': 'Preferencias de la App',
    'app_language_title': 'Idioma de la App',
    'current_lang_prefix': 'Actual',
    'silent_mode_desc': 'Silencia todas las notificaciones y tonos de llamada.',
    'section_panic_room': 'Sala de Pánico',
    'nuke_vault_title': 'DESTRUIR BÓVEDA: PURGAR Y DESTRUIR TODO',
    'nuke_vault_desc': 'Esta acción destruirá permanentemente tu ID de Privacidad, fondos cripto y todos los chats. Borra todo y te devuelve a la pantalla de activación.',
    'critical_warning_title': 'ADVERTENCIA CRÍTICA',
    'nuke_confirm_body': '¿Estás seguro de que quieres DESTRUIR la bóveda?\n\n⚠️ RETIRA TODOS LOS FONDOS CRIPTO Y GUARDA TUS ARCHIVOS ANTES DE CONTINUAR.\n\nEsta acción es irreversible. La aplicación quedará como recién instalada.',
    'nuke_everything_button': 'DESTRUIR TODO',
    'got_it_button': 'Entendido',
    'edit_name_title': 'Editar Nombre',
    'save_button': 'Guardar',
    'qr_code_button': 'Código QR',
    'copy_id_button': 'Copiar ID',
    'secure_crypto_vault_short': 'Secure\nCrypto Vault',
    'secure_vault_files_short': 'Secure\nVault Files',
    'privacy_id_label': 'ID de Privacidad',
    'profile_bio_paragraph': 'Construido con encriptación de Conocimiento Cero de nivel militar.\nTodas las comunicaciones funcionan estrictamente Peer-to-Peer (P2P).\nLos mensajes se autodestruyen automáticamente tras 24 horas\nusando sanitización de memoria antirrastreo segura.\nCero rastro, cero registros, privacidad total.',
    'close_button': 'Cerrar',
    'crypto_code_too_weak': 'El código es demasiado débil: usa al menos 10 caracteres y evita patrones repetidos o secuenciales.',
    'invalid_recovery_phrase': 'Frase de recuperación inválida - revisa las palabras e inténtalo de nuevo.',
    'crypto_vault_not_initialized': 'Crypto Vault no inicializado en este dispositivo.',
    'invalid_crypto_vault_code': 'Código de Crypto Vault inválido.',
    'crypto_vault_corrupted': 'Los datos del Crypto Vault están corruptos (el código era correcto, pero el propio archivo de la bóveda está dañado).',
    'create_crypto_vault_code_title': 'CREAR CÓDIGO DE CRYPTO VAULT',
    'enter_crypto_vault_code_title': 'INTRODUCIR CÓDIGO DE CRYPTO VAULT',
    'crypto_code_desc_create': 'Este código es independiente de los códigos de la app y de Vault Files. Protege una billetera nueva, no custodial, que solo tú controlas.',
    'crypto_code_desc_enter': 'Introduce tu código de Crypto Vault para acceder a tu billetera.',
    'create_new_wallet_instead': '← Crear una billetera nueva en su lugar',
    'already_have_recovery_phrase': 'Ya tengo una frase de recuperación (perdí el móvil / reinstalé)',
    'recovery_phrase_label': 'Tu frase de recuperación de 12 palabras',
    'recovery_phrase_hint': 'palabra1 palabra2 palabra3 ...',
    'set_crypto_vault_code_label': 'Establecer Código de Crypto Vault (para ESTE dispositivo)',
    'crypto_vault_code_label': 'Código de Crypto Vault',
    'restore_wallet_button': 'RESTAURAR BILLETERA',
    'create_wallet_button': 'CREAR BILLETERA',
    'unlock_button': 'DESBLOQUEAR',
    'recovery_phrase_title': 'Tu Frase de Recuperación',
    'recovery_phrase_warning': '⚠️ Escribe estas 12 palabras en papel, en orden, y guárdalas en un lugar seguro y sin conexión. Cualquiera con estas palabras puede robar tus fondos. Padlock NO guarda esta frase en ningún sitio ni puede recuperarla por ti.',
    'recovery_phrase_confirm_checkbox': 'Ya escribí estas palabras y las guardé de forma segura sin conexión.',
    'continue_button': 'CONTINUAR',
    'loading_text': 'Cargando...',
    'could_not_load_balance': 'No se pudo cargar el saldo',
    'receive_dialog_title': 'Recibir',
    'receive_address_warning': 'Escanear o compartir este código solo da la DIRECCIÓN de tu billetera - nunca tu frase de recuperación.',
    'address_copied_toast': 'Dirección copiada.',
    'copy_button': 'COPIAR',
    'testnet_warning': '⚠️ RED DE PRUEBA (Polygon Amoy) - esto NO son fondos reales.',
    'balances_label': 'Saldos',
    'receive_button': 'RECIBIR',
    'send_button': 'ENVIAR',
    'camera_permission_denied': 'Permiso de cámara denegado. Actívalo en Ajustes del teléfono > Apps > Padlock > Permisos.',
    'scan_wallet_address_title': 'Escanear Dirección de Billetera',
    'invalid_wallet_address': 'Dirección de billetera inválida.',
    'enter_valid_amount': 'Introduce un monto válido.',
    'price_not_loaded': 'La cotización aún no se cargó - inténtalo de nuevo en un momento.',
    'transaction_sent_title': 'Transacción Enviada',
    'done_button': 'HECHO',
    'send_failed_prefix': 'Error al enviar',
    'send_title': 'Enviar',
    'recipient_address_label': 'Dirección de la billetera del destinatario',
    'coin_label': 'Moneda',
    'amount_in_label': 'Monto en:',
    'amount_usd_label': 'Monto (USD)',
    'amount_label_prefix': 'Monto',
    'loading_price': 'Cargando cotización...',
    'price_label_prefix': 'Cotización',
    'confirm_send_button': 'CONFIRMAR Y ENVIAR',
    'vault_files_not_initialized': 'Vault Files no está inicializado en este dispositivo.',
    'invalid_vault_files_code': 'Código de Vault Files inválido.',
    'vault_files_corrupted': 'Los datos de Vault Files están dañados (el código era correcto, pero el propio archivo de la caja fuerte está dañado).',
    'create_vault_files_code_title': 'CREAR CÓDIGO DE VAULT FILES',
    'enter_vault_files_code_title': 'INTRODUCIR CÓDIGO DE VAULT FILES',
    'vault_files_code_desc_create': 'Este código es distinto del código de desbloqueo de la app. Quien conozca el código de la app NO podrá abrir tus fotos y documentos sin este también.',
    'vault_files_code_desc_enter': 'Introduce tu código de Vault Files para ver tus fotos y documentos cifrados.',
    'set_vault_files_code_label': 'Establecer Código de Vault Files',
    'vault_files_code_label': 'Código de Vault Files',
    'create_vault_button': 'CREAR CAJA FUERTE',
    'imported_skipped_toast': '{imported} importados, {skipped} omitidos (máx. {mb}MB cada uno).',
    'no_contacts_yet': 'Aún no tienes contactos.',
    'send_to_title': 'Enviar a...',
    'sent_toast': 'Enviado.',
    'failed_to_send_prefix': 'Error al enviar',
    'received_from_prefix': 'Recibido de',
    'sent_to_prefix': 'Enviado a',
    'stored_locally_not_sent': 'Guardado localmente — aún no enviado a nadie',
    'document_label': 'Documento',
    'document_stored_encrypted_desc': 'Este documento está guardado cifrado en tu Vault Files ({kb} KB). Usa Exportar para guardarlo de nuevo en tu teléfono o compartirlo.',
    'export_button': 'Exportar',
    'personal_files_empty': 'Aún no tienes archivos personales.\nUsa el botón + para tomar una foto o importar un documento.',
    'received_files_empty': 'Aún no has recibido nada.',
    'sent_files_empty': 'Aún no has enviado nada.',
    'tab_personal': 'Personal',
    'tab_received': 'Recibidos',
    'tab_sent': 'Enviados',
    'copy_message': 'Copiar Mensaje',
    'destroy_message': 'Destruir Mensaje',
    'node_destruction_title': 'Destrucción de Nodo',
    'destroy_message_confirm_body': '¿Deseas destruir este mensaje permanentemente en ambos dispositivos?',
    'destroy_button': 'Destruir',
    'failed_to_send_photo_prefix': 'Error al enviar foto',
    'encrypted_photo_sent_message': '🖼️ Foto cifrada enviada — ver en Secure Vault Files',
    'photo_chat_preview': '🖼️ Foto',
    'just_now': 'Justo Ahora',
    'failed_to_send_voice_prefix': 'Error al enviar mensaje de voz',
    'voice_message_chat_preview': '🎤 Mensaje de voz',
    'voice_message_label': 'Mensaje de voz',
    'no_secure_channel_error': 'No se pudo enviar: aún no hay un canal seguro con este contacto ({error}). Intenta eliminarlo y volver a añadirlo.',
    'block_id_title': 'Bloquear ID',
    'block_id_confirm_body': '¿Deseas bloquear permanentemente este ID?',
    'block_button': 'Bloquear',
    'keys_not_available': 'Claves no disponibles para este contacto.',
    'safety_number_title': 'Número de Seguridad',
    'safety_number_desc': 'Haz una llamada segura a este contacto y lee este número en voz alta. Si coincide en ambos dispositivos, nadie está interceptando tu conversación.',
    'verify_safety_number': 'Verificar Número de Seguridad',
    'encrypted_p2p_channel': 'Canal P2P Cifrado',
    'destruct_1m': '1 Minuto',
    'destruct_5m': '5 Minutos',
    'destruct_1h': '1 Hora',
    'destruct_24h': '24 Horas',
    'message_not_decrypted': '[Mensaje no descifrado]',
    'call_status_connecting': 'Conectando...',
    'call_status_exchanging_keys': 'Intercambiando claves de cifrado...',
    'call_status_ringing': 'Sonando...',
    'call_status_connecting_encrypted': 'Conectando llamada cifrada...',
    'call_status_incoming_encrypted': 'Llamada cifrada entrante...',
    'call_status_connected_prefix': 'Conectado',
    'call_status_connected_encrypted': 'Conectado y cifrado',
    'call_status_reconnecting': 'Reconectando...',
    'call_contact_unavailable': 'Contacto no disponible o desconectado.',
    'missed_secure_call': 'Llamada Segura Perdida',
    'missed_call_notification_title': 'Llamada Perdida',
    'setup_code_too_weak': 'La clave de descifrado es demasiado débil: usa al menos 10 caracteres y evita patrones repetidos o secuenciales.',
    'vault_init_failed_prefix': 'Error al inicializar la bóveda',
    'create_vault_title': 'CREA TU BÓVEDA CIFRADA',
    'create_vault_subtitle': 'Establece tu clave maestra para generar\ntu identidad criptográfica P2P',
    'set_decryption_key_label': 'Establecer Clave de Descifrado',
    'strength_too_weak': 'Demasiado débil',
    'strength_weak': 'Débil',
    'strength_medium': 'Media',
    'strength_strong': 'Fuerte',
    'strength_very_strong': 'Muy fuerte',
    'initialize_vault_button': 'INICIALIZAR BÓVEDA',
    'footer_privacy_text': 'Diseñado con cifrado Zero-Knowledge de nivel militar.\nTodas las comunicaciones operan estrictamente Peer-to-Peer (P2P).\nLos mensajes se autodestruyen automáticamente después de 24 horas\nusando saneamiento de memoria anti-rastro seguro.\nCero rastro, cero registros, privacidad total.',
    'vault_not_initialized_device': 'Bóveda no inicializada en este dispositivo.',
    'invalid_decryption_key': 'Clave de Descifrado inválida.',
    'vault_data_corrupted': 'Los datos de la bóveda están dañados (la clave era correcta, pero el propio archivo de la bóveda está dañado).',
    'decrypt_padlock_title': 'DESCIFRA TU PADLOCK',
    'login_subtitle': 'DISEÑADO CON CIFRADO ZERO-KNOWLEDGE\nDE NIVEL MILITAR',
    'enter_decryption_key_label': 'Introducir Clave de Descifrado',
    'access_vault_button': 'ACCEDER A LA BÓVEDA',
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
    'language': 'Langue',
    'search_contact_hint': 'Rechercher un contact...',
    'encrypted_p2p_contact': 'Contact P2P Crypté',
    'encrypted_p2p_message_preview': '[Message P2P Crypté]',
    'delete_chat_confirm_title': 'Supprimer la Conversation',
    'delete_chat_confirm_body': 'Voulez-vous supprimer définitivement cette conversation ?',
    'cancel_button': 'Annuler',
    'delete_button': 'Supprimer',
    'settings_header': 'PARAMÈTRES',
    'section_core_security': 'Protocoles de Sécurité Principaux',
    'info_encryption_title': 'Chiffrement de Niveau Militaire',
    'info_encryption_desc': 'Norme AES-256-GCM et Curve25519.',
    'info_p2p_title': 'Véritable Pair-à-Pair',
    'info_p2p_desc': 'Voix et données directes. Aucun routage par serveur.',
    'info_autodestruct_title': 'Autodestruction Forensique',
    'info_autodestruct_desc': 'Tous les messages sont détruits en 24 heures maximum.',
    'info_screenshot_title': 'Protection Contre les Captures d\'Écran',
    'info_screenshot_desc': 'La capture d\'écran est bloquée globalement dans toute l\'app pour éviter les fuites de données non autorisées.',
    'info_timeout_title': 'Fermeture Automatique Sécurisée',
    'info_timeout_desc': 'L\'app se ferme automatiquement après 15 minutes d\'utilisation, pour votre sécurité. Une nouvelle connexion est nécessaire pour continuer. Les appels actifs ignorent cette règle pour maintenir la connexion.',
    'section_premium': 'Padlock Premium',
    'secure_crypto_vault_title': 'Secure Crypto Vault',
    'crypto_vault_desc': 'Stockage de sécurité maximale pour vos actifs numériques.',
    'section_help_center': 'Centre d\'Aide / Comment Utiliser',
    'help_vault_files_q': 'Comment utiliser Secure Vault Files ?',
    'help_vault_files_a': 'Pour accéder à cette section, vous devez créer une clé chiffrée dédiée. Chaque fois que vous ouvrez le coffre, il vous demandera cette clé pour vous connecter, comme la connexion de sécurité de l\'app.\n\n• Toutes les photos prises directement dans Padlock sont enregistrées ici automatiquement.\n• Les documents et photos envoyés par des contacts vers votre ID sont directement dirigés vers ce coffre au lieu des chats normaux. Vous recevrez une alerte indiquant qu\'un contenu a été envoyé, et vous devrez y accéder dans le coffre pour le voir.\n• Les fichiers restent chiffrés et sécurisés à 100 % jusqu\'à leur suppression, exportation ou renvoi manuel.',
    'help_add_contact_q': 'Comment ajouter un contact ?',
    'help_add_contact_a': 'Allez dans l\'onglet "Contacts", appuyez sur le bouton bleu (+), et collez un ID de confidentialité ou utilisez le scanner QR vert.',
    'help_share_id_q': 'Comment partager mon ID ?',
    'help_share_id_a': 'Allez dans l\'onglet "Profil". Appuyez sur "Copy ID" pour le coller en toute sécurité n\'importe où, ou sur "QR Code" pour que quelqu\'un scanne votre écran.',
    'help_rename_contact_q': 'Comment renommer un contact ?',
    'help_rename_contact_a': 'Dans l\'onglet "Contacts", appuyez sur l\'icône Modifier (crayon) à côté d\'un contact pour changer son nom affiché.',
    'help_delete_contact_q': 'Comment supprimer un contact ?',
    'help_delete_contact_a': 'Dans l\'onglet "Contacts", appuyez longuement sur un contact. Cela le supprimera définitivement et détruira les clés de chiffrement partagées.',
    'help_wipe_chat_q': 'Comment effacer une conversation ?',
    'help_wipe_chat_a': 'Dans n\'importe quelle conversation active, appuyez sur le menu (trois points) en haut à droite et sélectionnez "Supprimer la Conversation" pour détruire tous les messages sur les deux appareils.',
    'section_app_preferences': 'Préférences de l\'App',
    'app_language_title': 'Langue de l\'App',
    'current_lang_prefix': 'Actuelle',
    'silent_mode_desc': 'Coupe toutes les notifications et sonneries d\'appel.',
    'section_panic_room': 'Salle de Panique',
    'nuke_vault_title': 'DÉTRUIRE LE COFFRE : PURGER ET TOUT DÉTRUIRE',
    'nuke_vault_desc': 'Cette action détruira définitivement votre ID de confidentialité, vos fonds crypto et toutes vos conversations. Elle efface tout et vous ramène à l\'écran d\'activation.',
    'critical_warning_title': 'AVERTISSEMENT CRITIQUE',
    'nuke_confirm_body': 'Êtes-vous sûr de vouloir DÉTRUIRE le coffre ?\n\n⚠️ RETIREZ TOUS LES FONDS CRYPTO ET SAUVEGARDEZ VOS FICHIERS AVANT DE CONTINUER.\n\nCette action est irréversible. L\'application reviendra à un état d\'usine.',
    'nuke_everything_button': 'TOUT DÉTRUIRE',
    'got_it_button': 'Compris',
    'edit_name_title': 'Modifier le Nom',
    'save_button': 'Enregistrer',
    'qr_code_button': 'Code QR',
    'copy_id_button': 'Copier l\'ID',
    'secure_crypto_vault_short': 'Secure\nCrypto Vault',
    'secure_vault_files_short': 'Secure\nVault Files',
    'privacy_id_label': 'ID de Confidentialité',
    'profile_bio_paragraph': 'Conçu avec un chiffrement Zero-Knowledge de niveau militaire.\nToutes les communications fonctionnent strictement en Pair-à-Pair (P2P).\nLes messages s\'autodétruisent automatiquement après 24 heures\nen utilisant une désinfection de mémoire anti-traçage sécurisée.\nAucune trace, aucun journal, confidentialité totale.',
    'close_button': 'Fermer',
    'crypto_code_too_weak': 'Le code est trop faible : utilisez au moins 10 caractères et évitez les motifs répétés ou séquentiels.',
    'invalid_recovery_phrase': 'Phrase de récupération invalide - vérifiez les mots et réessayez.',
    'crypto_vault_not_initialized': 'Crypto Vault non initialisé sur cet appareil.',
    'invalid_crypto_vault_code': 'Code de Crypto Vault invalide.',
    'crypto_vault_corrupted': 'Les données du Crypto Vault sont corrompues (le code était correct, mais le fichier du coffre lui-même est endommagé).',
    'create_crypto_vault_code_title': 'CRÉER UN CODE CRYPTO VAULT',
    'enter_crypto_vault_code_title': 'ENTRER LE CODE CRYPTO VAULT',
    'crypto_code_desc_create': 'Ce code est distinct des codes de l\'app et de Vault Files. Il protège un tout nouveau portefeuille non dépositaire que vous seul contrôlez.',
    'crypto_code_desc_enter': 'Entrez votre code Crypto Vault pour accéder à votre portefeuille.',
    'create_new_wallet_instead': '← Créer un nouveau portefeuille à la place',
    'already_have_recovery_phrase': 'J\'ai déjà une phrase de récupération (téléphone perdu / réinstallation)',
    'recovery_phrase_label': 'Votre phrase de récupération de 12 mots',
    'recovery_phrase_hint': 'mot1 mot2 mot3 ...',
    'set_crypto_vault_code_label': 'Définir le Code Crypto Vault (pour CET appareil)',
    'crypto_vault_code_label': 'Code Crypto Vault',
    'restore_wallet_button': 'RESTAURER LE PORTEFEUILLE',
    'create_wallet_button': 'CRÉER LE PORTEFEUILLE',
    'unlock_button': 'DÉVERROUILLER',
    'recovery_phrase_title': 'Votre Phrase de Récupération',
    'recovery_phrase_warning': '⚠️ Écrivez ces 12 mots sur papier, dans l\'ordre, et conservez-les dans un endroit sûr et hors ligne. Quiconque possède ces mots peut voler vos fonds. Padlock NE stocke PAS cette phrase et ne peut pas la récupérer pour vous.',
    'recovery_phrase_confirm_checkbox': 'J\'ai écrit ces mots et je les ai stockés en sécurité hors ligne.',
    'continue_button': 'CONTINUER',
    'loading_text': 'Chargement...',
    'could_not_load_balance': 'Impossible de charger le solde',
    'receive_dialog_title': 'Recevoir',
    'receive_address_warning': 'Scanner ou partager ce code ne donne que l\'ADRESSE de votre portefeuille - jamais votre phrase de récupération.',
    'address_copied_toast': 'Adresse copiée.',
    'copy_button': 'COPIER',
    'testnet_warning': '⚠️ RÉSEAU DE TEST (Polygon Amoy) - ce ne sont PAS des fonds réels.',
    'balances_label': 'Soldes',
    'receive_button': 'RECEVOIR',
    'send_button': 'ENVOYER',
    'camera_permission_denied': 'Permission caméra refusée. Activez-la dans Paramètres du téléphone > Applications > Padlock > Permissions.',
    'scan_wallet_address_title': 'Scanner l\'Adresse du Portefeuille',
    'invalid_wallet_address': 'Adresse de portefeuille invalide.',
    'enter_valid_amount': 'Entrez un montant valide.',
    'price_not_loaded': 'Le cours n\'est pas encore chargé - réessayez dans un instant.',
    'transaction_sent_title': 'Transaction Envoyée',
    'done_button': 'TERMINÉ',
    'send_failed_prefix': 'Échec de l\'envoi',
    'send_title': 'Envoyer',
    'recipient_address_label': 'Adresse du portefeuille du destinataire',
    'coin_label': 'Devise',
    'amount_in_label': 'Montant en :',
    'amount_usd_label': 'Montant (USD)',
    'amount_label_prefix': 'Montant',
    'loading_price': 'Chargement du cours...',
    'price_label_prefix': 'Cours',
    'confirm_send_button': 'CONFIRMER ET ENVOYER',
    'vault_files_not_initialized': 'Vault Files n\'est pas initialisé sur cet appareil.',
    'invalid_vault_files_code': 'Code Vault Files invalide.',
    'vault_files_corrupted': 'Les données de Vault Files sont corrompues (le code était correct, mais le fichier du coffre lui-même est endommagé).',
    'create_vault_files_code_title': 'CRÉER LE CODE VAULT FILES',
    'enter_vault_files_code_title': 'SAISIR LE CODE VAULT FILES',
    'vault_files_code_desc_create': 'Ce code est distinct du code de déverrouillage de l\'application. Quiconque connaît le code de l\'application NE pourra PAS ouvrir vos photos et documents sans celui-ci également.',
    'vault_files_code_desc_enter': 'Saisissez votre code Vault Files pour consulter vos photos et documents chiffrés.',
    'set_vault_files_code_label': 'Définir le Code Vault Files',
    'vault_files_code_label': 'Code Vault Files',
    'create_vault_button': 'CRÉER LE COFFRE',
    'imported_skipped_toast': '{imported} importé(s), {skipped} ignoré(s) (max {mb}Mo chacun).',
    'no_contacts_yet': 'Pas encore de contacts.',
    'send_to_title': 'Envoyer à...',
    'sent_toast': 'Envoyé.',
    'failed_to_send_prefix': 'Échec de l\'envoi',
    'received_from_prefix': 'Reçu de',
    'sent_to_prefix': 'Envoyé à',
    'stored_locally_not_sent': 'Stocké localement — pas encore envoyé à qui que ce soit',
    'document_label': 'Document',
    'document_stored_encrypted_desc': 'Ce document est stocké chiffré dans votre Vault Files ({kb} Ko). Utilisez Exporter pour le sauvegarder sur votre téléphone ou le partager.',
    'export_button': 'Exporter',
    'personal_files_empty': 'Pas encore de fichiers personnels.\nUtilisez le bouton + pour prendre une photo ou importer un document.',
    'received_files_empty': 'Rien reçu pour l\'instant.',
    'sent_files_empty': 'Rien envoyé pour l\'instant.',
    'tab_personal': 'Personnel',
    'tab_received': 'Reçus',
    'tab_sent': 'Envoyés',
    'copy_message': 'Copier le Message',
    'destroy_message': 'Détruire le Message',
    'node_destruction_title': 'Destruction de Nœud',
    'destroy_message_confirm_body': 'Voulez-vous détruire définitivement ce message sur les deux appareils ?',
    'destroy_button': 'Détruire',
    'failed_to_send_photo_prefix': 'Échec de l\'envoi de la photo',
    'encrypted_photo_sent_message': '🖼️ Photo chiffrée envoyée — voir dans Secure Vault Files',
    'photo_chat_preview': '🖼️ Photo',
    'just_now': 'À l\'instant',
    'failed_to_send_voice_prefix': 'Échec de l\'envoi du message vocal',
    'voice_message_chat_preview': '🎤 Message vocal',
    'voice_message_label': 'Message vocal',
    'no_secure_channel_error': 'Envoi impossible : pas encore de canal sécurisé avec ce contact ({error}). Essayez de le supprimer puis de l\'ajouter à nouveau.',
    'block_id_title': 'Bloquer l\'ID',
    'block_id_confirm_body': 'Voulez-vous bloquer définitivement cet ID ?',
    'block_button': 'Bloquer',
    'keys_not_available': 'Clés non disponibles pour ce contact.',
    'safety_number_title': 'Numéro de Sécurité',
    'safety_number_desc': 'Passez un appel sécurisé à ce contact et lisez ce numéro à voix haute. S\'il correspond sur les deux appareils, personne n\'intercepte votre conversation.',
    'verify_safety_number': 'Vérifier le Numéro de Sécurité',
    'encrypted_p2p_channel': 'Canal P2P Chiffré',
    'destruct_1m': '1 Minute',
    'destruct_5m': '5 Minutes',
    'destruct_1h': '1 Heure',
    'destruct_24h': '24 Heures',
    'message_not_decrypted': '[Message non déchiffré]',
    'call_status_connecting': 'Connexion...',
    'call_status_exchanging_keys': 'Échange des clés de chiffrement...',
    'call_status_ringing': 'Sonnerie...',
    'call_status_connecting_encrypted': 'Connexion d\'un appel chiffré...',
    'call_status_incoming_encrypted': 'Appel chiffré entrant...',
    'call_status_connected_prefix': 'Connecté',
    'call_status_connected_encrypted': 'Connecté et chiffré',
    'call_status_reconnecting': 'Reconnexion...',
    'call_contact_unavailable': 'Contact indisponible ou hors ligne.',
    'missed_secure_call': 'Appel Sécurisé Manqué',
    'missed_call_notification_title': 'Appel Manqué',
    'setup_code_too_weak': 'La clé de déchiffrement est trop faible : utilisez au moins 10 caractères et évitez les motifs répétés ou séquentiels.',
    'vault_init_failed_prefix': 'Échec de l\'initialisation du coffre',
    'create_vault_title': 'CRÉEZ VOTRE COFFRE CHIFFRÉ',
    'create_vault_subtitle': 'Définissez votre clé maîtresse pour générer\nvotre identité cryptographique P2P',
    'set_decryption_key_label': 'Définir la Clé de Déchiffrement',
    'strength_too_weak': 'Trop faible',
    'strength_weak': 'Faible',
    'strength_medium': 'Moyenne',
    'strength_strong': 'Forte',
    'strength_very_strong': 'Très forte',
    'initialize_vault_button': 'INITIALISER LE COFFRE',
    'footer_privacy_text': 'Conçu avec un chiffrement Zero-Knowledge de niveau militaire.\nToutes les communications fonctionnent strictement en Pair-à-Pair (P2P).\nLes messages s\'autodétruisent automatiquement après 24 heures\nà l\'aide d\'une désinfection sécurisée de la mémoire anti-trace.\nZéro trace, zéro journal, confidentialité totale.',
    'vault_not_initialized_device': 'Coffre non initialisé sur cet appareil.',
    'invalid_decryption_key': 'Clé de Déchiffrement invalide.',
    'vault_data_corrupted': 'Les données du coffre sont corrompues (la clé était correcte, mais le fichier du coffre lui-même est endommagé).',
    'decrypt_padlock_title': 'DÉCHIFFREZ VOTRE PADLOCK',
    'login_subtitle': 'CONÇU AVEC UN CHIFFREMENT ZERO-KNOWLEDGE\nDE NIVEAU MILITAIRE',
    'enter_decryption_key_label': 'Saisir la Clé de Déchiffrement',
    'access_vault_button': 'ACCÉDER AU COFFRE',
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
    'language': 'Sprache',
    'search_contact_hint': 'Kontakt suchen...',
    'encrypted_p2p_contact': 'Verschlüsselter P2P-Kontakt',
    'encrypted_p2p_message_preview': '[Verschlüsselte P2P-Nachricht]',
    'delete_chat_confirm_title': 'Chat löschen',
    'delete_chat_confirm_body': 'Möchten Sie diesen Chat dauerhaft löschen?',
    'cancel_button': 'Abbrechen',
    'delete_button': 'Löschen',
    'settings_header': 'EINSTELLUNGEN',
    'section_core_security': 'Zentrale Sicherheitsprotokolle',
    'info_encryption_title': 'Militärische Verschlüsselung',
    'info_encryption_desc': 'AES-256-GCM- und Curve25519-Standard.',
    'info_p2p_title': 'Echtes Peer-to-Peer',
    'info_p2p_desc': 'Direkte Sprache & Daten. Kein Server-Routing.',
    'info_autodestruct_title': 'Forensische Selbstzerstörung',
    'info_autodestruct_desc': 'Alle Nachrichten werden innerhalb von maximal 24 Stunden vernichtet.',
    'info_screenshot_title': 'Screenshot-Schutz',
    'info_screenshot_desc': 'Bildschirmaufnahmen sind app-weit blockiert, um unbefugte Datenlecks zu verhindern.',
    'info_timeout_title': 'Sichere Auszeit',
    'info_timeout_desc': 'Die App schließt sich zu Ihrer Sicherheit automatisch nach 15 Minuten Nutzung. Zum Fortsetzen ist eine erneute Anmeldung erforderlich. Aktive Anrufe umgehen diese Regel, um die Verbindung aufrechtzuerhalten.',
    'section_premium': 'Padlock Premium',
    'secure_crypto_vault_title': 'Secure Crypto Vault',
    'crypto_vault_desc': 'Speicher mit maximaler Sicherheit für Ihre digitalen Vermögenswerte.',
    'section_help_center': 'Hilfezentrum / Anleitung',
    'help_vault_files_q': 'Wie benutzt man Secure Vault Files?',
    'help_vault_files_a': 'Um auf diesen Bereich zuzugreifen, müssen Sie einen eigenen verschlüsselten Schlüssel erstellen. Jedes Mal, wenn Sie den Tresor öffnen, wird dieser Schlüssel zur Anmeldung abgefragt, genau wie bei der App-Sicherheitsanmeldung.\n\n• Alle direkt in Padlock aufgenommenen Fotos werden hier automatisch gespeichert.\n• Von Kontakten an Ihre ID gesendete Dokumente und Fotos werden direkt in diesen Tresor statt in normale Chats geleitet. Sie erhalten eine Benachrichtigung, dass Inhalte gesendet wurden, und müssen im Tresor darauf zugreifen, um sie anzusehen.\n• Dateien bleiben zu 100 % verschlüsselt und sicher, bis sie manuell gelöscht, exportiert oder erneut gesendet werden.',
    'help_add_contact_q': 'Wie fügt man einen Kontakt hinzu?',
    'help_add_contact_a': 'Gehen Sie zum Tab "Kontakte", tippen Sie auf die blaue (+) Schaltfläche und fügen Sie eine Datenschutz-ID ein oder verwenden Sie den grünen QR-Scanner.',
    'help_share_id_q': 'Wie teile ich meine ID?',
    'help_share_id_a': 'Gehen Sie zum Tab "Profil". Tippen Sie auf "Copy ID", um sie sicher überall einzufügen, oder auf "QR Code", damit jemand Ihren Bildschirm scannen kann.',
    'help_rename_contact_q': 'Wie benennt man einen Kontakt um?',
    'help_rename_contact_a': 'Tippen Sie im Tab "Kontakte" auf das Bearbeiten-Symbol (Stift) neben einem Kontakt, um dessen Anzeigenamen zu ändern.',
    'help_delete_contact_q': 'Wie löscht man einen Kontakt?',
    'help_delete_contact_a': 'Halten Sie im Tab "Kontakte" einen Kontakt gedrückt. Dadurch wird er dauerhaft gelöscht und die gemeinsamen Verschlüsselungsschlüssel werden vernichtet.',
    'help_wipe_chat_q': 'Wie löscht man eine Unterhaltung?',
    'help_wipe_chat_a': 'Tippen Sie in einem aktiven Chat auf das Menü (drei Punkte) oben rechts und wählen Sie "Konversation löschen", um alle Nachrichten auf beiden Geräten zu vernichten.',
    'section_app_preferences': 'App-Einstellungen',
    'app_language_title': 'App-Sprache',
    'current_lang_prefix': 'Aktuell',
    'silent_mode_desc': 'Stummschaltung aller Benachrichtigungen und Anruftöne.',
    'section_panic_room': 'Panikraum',
    'nuke_vault_title': 'TRESOR VERNICHTEN: ALLES LÖSCHEN UND ZERSTÖREN',
    'nuke_vault_desc': 'Diese Aktion vernichtet dauerhaft Ihre Datenschutz-ID, Krypto-Guthaben und alle Chats. Sie löscht alles und bringt Sie zurück zum Aktivierungsbildschirm.',
    'critical_warning_title': 'KRITISCHE WARNUNG',
    'nuke_confirm_body': 'Sind Sie sicher, dass Sie den Tresor VERNICHTEN möchten?\n\n⚠️ HEBEN SIE ALLE KRYPTO-GUTHABEN AB UND SICHERN SIE IHRE DATEIEN, BEVOR SIE FORTFAHREN.\n\nDiese Aktion ist unwiderruflich. Die Anwendung wird auf den Werkszustand zurückgesetzt.',
    'nuke_everything_button': 'ALLES VERNICHTEN',
    'got_it_button': 'Verstanden',
    'edit_name_title': 'Namen Bearbeiten',
    'save_button': 'Speichern',
    'qr_code_button': 'QR-Code',
    'copy_id_button': 'ID Kopieren',
    'secure_crypto_vault_short': 'Secure\nCrypto Vault',
    'secure_vault_files_short': 'Secure\nVault Files',
    'privacy_id_label': 'Datenschutz-ID',
    'profile_bio_paragraph': 'Entwickelt mit militärischer Zero-Knowledge-Verschlüsselung.\nAlle Kommunikationen erfolgen strikt Peer-to-Peer (P2P).\nNachrichten werden nach 24 Stunden automatisch selbst zerstört\ndurch sichere Anti-Trace-Speicherbereinigung.\nKeine Spuren, keine Protokolle, totale Privatsphäre.',
    'close_button': 'Schließen',
    'crypto_code_too_weak': 'Der Code ist zu schwach: Verwenden Sie mindestens 10 Zeichen und vermeiden Sie wiederholte oder fortlaufende Muster.',
    'invalid_recovery_phrase': 'Ungültige Wiederherstellungsphrase - überprüfen Sie die Wörter und versuchen Sie es erneut.',
    'crypto_vault_not_initialized': 'Crypto Vault auf diesem Gerät nicht initialisiert.',
    'invalid_crypto_vault_code': 'Ungültiger Crypto-Vault-Code.',
    'crypto_vault_corrupted': 'Die Crypto-Vault-Daten sind beschädigt (der Code war korrekt, aber die Tresordatei selbst ist beschädigt).',
    'create_crypto_vault_code_title': 'CRYPTO-VAULT-CODE ERSTELLEN',
    'enter_crypto_vault_code_title': 'CRYPTO-VAULT-CODE EINGEBEN',
    'crypto_code_desc_create': 'Dieser Code ist getrennt von den Codes der App und von Vault Files. Er schützt eine brandneue, nicht verwahrte Wallet, die nur Sie kontrollieren.',
    'crypto_code_desc_enter': 'Geben Sie Ihren Crypto-Vault-Code ein, um auf Ihre Wallet zuzugreifen.',
    'create_new_wallet_instead': '← Stattdessen eine neue Wallet erstellen',
    'already_have_recovery_phrase': 'Ich habe bereits eine Wiederherstellungsphrase (Telefon verloren / neu installiert)',
    'recovery_phrase_label': 'Ihre 12-Wörter-Wiederherstellungsphrase',
    'recovery_phrase_hint': 'wort1 wort2 wort3 ...',
    'set_crypto_vault_code_label': 'Crypto-Vault-Code festlegen (für DIESES Gerät)',
    'crypto_vault_code_label': 'Crypto-Vault-Code',
    'restore_wallet_button': 'WALLET WIEDERHERSTELLEN',
    'create_wallet_button': 'WALLET ERSTELLEN',
    'unlock_button': 'ENTSPERREN',
    'recovery_phrase_title': 'Ihre Wiederherstellungsphrase',
    'recovery_phrase_warning': '⚠️ Schreiben Sie diese 12 Wörter in der richtigen Reihenfolge auf Papier und bewahren Sie sie an einem sicheren Ort offline auf. Jeder mit diesen Wörtern kann Ihre Gelder stehlen. Padlock speichert diese Phrase NICHT und kann sie nicht für Sie wiederherstellen.',
    'recovery_phrase_confirm_checkbox': 'Ich habe diese Wörter aufgeschrieben und sicher offline aufbewahrt.',
    'continue_button': 'WEITER',
    'loading_text': 'Wird geladen...',
    'could_not_load_balance': 'Guthaben konnte nicht geladen werden',
    'receive_dialog_title': 'Empfangen',
    'receive_address_warning': 'Das Scannen oder Teilen dieses Codes gibt nur die ADRESSE Ihrer Wallet preis - niemals Ihre Wiederherstellungsphrase.',
    'address_copied_toast': 'Adresse kopiert.',
    'copy_button': 'KOPIEREN',
    'testnet_warning': '⚠️ TESTNETZ (Polygon Amoy) - dies ist KEIN echtes Geld.',
    'balances_label': 'Guthaben',
    'receive_button': 'EMPFANGEN',
    'send_button': 'SENDEN',
    'camera_permission_denied': 'Kamerazugriff verweigert. Aktivieren Sie ihn in den Telefoneinstellungen > Apps > Padlock > Berechtigungen.',
    'scan_wallet_address_title': 'Wallet-Adresse scannen',
    'invalid_wallet_address': 'Ungültige Wallet-Adresse.',
    'enter_valid_amount': 'Geben Sie einen gültigen Betrag ein.',
    'price_not_loaded': 'Kurs noch nicht geladen - versuchen Sie es gleich noch einmal.',
    'transaction_sent_title': 'Transaktion Gesendet',
    'done_button': 'FERTIG',
    'send_failed_prefix': 'Senden fehlgeschlagen',
    'send_title': 'Senden',
    'recipient_address_label': 'Wallet-Adresse des Empfängers',
    'coin_label': 'Münze',
    'amount_in_label': 'Betrag in:',
    'amount_usd_label': 'Betrag (USD)',
    'amount_label_prefix': 'Betrag',
    'loading_price': 'Kurs wird geladen...',
    'price_label_prefix': 'Kurs',
    'confirm_send_button': 'BESTÄTIGEN & SENDEN',
    'vault_files_not_initialized': 'Vault Files ist auf diesem Gerät nicht initialisiert.',
    'invalid_vault_files_code': 'Ungültiger Vault Files-Code.',
    'vault_files_corrupted': 'Vault Files-Daten sind beschädigt (Code war korrekt, aber die Tresordatei selbst ist beschädigt).',
    'create_vault_files_code_title': 'VAULT FILES-CODE ERSTELLEN',
    'enter_vault_files_code_title': 'VAULT FILES-CODE EINGEBEN',
    'vault_files_code_desc_create': 'Dieser Code ist getrennt von deinem App-Entsperrcode. Wer deinen App-Code kennt, kann deine Fotos und Dokumente OHNE diesen zusätzlichen Code nicht öffnen.',
    'vault_files_code_desc_enter': 'Gib deinen Vault Files-Code ein, um deine verschlüsselten Fotos und Dokumente anzusehen.',
    'set_vault_files_code_label': 'Vault Files-Code festlegen',
    'vault_files_code_label': 'Vault Files-Code',
    'create_vault_button': 'TRESOR ERSTELLEN',
    'imported_skipped_toast': '{imported} importiert, {skipped} übersprungen (max. {mb}MB je Datei).',
    'no_contacts_yet': 'Noch keine Kontakte.',
    'send_to_title': 'Senden an...',
    'sent_toast': 'Gesendet.',
    'failed_to_send_prefix': 'Senden fehlgeschlagen',
    'received_from_prefix': 'Empfangen von',
    'sent_to_prefix': 'Gesendet an',
    'stored_locally_not_sent': 'Lokal gespeichert — noch an niemanden gesendet',
    'document_label': 'Dokument',
    'document_stored_encrypted_desc': 'Dieses Dokument ist verschlüsselt in deinem Vault Files gespeichert ({kb} KB). Nutze Exportieren, um es wieder auf dein Telefon zu speichern oder zu teilen.',
    'export_button': 'Exportieren',
    'personal_files_empty': 'Noch keine persönlichen Dateien.\nNutze die +-Schaltfläche, um ein Foto aufzunehmen oder ein Dokument zu importieren.',
    'received_files_empty': 'Noch nichts empfangen.',
    'sent_files_empty': 'Noch nichts gesendet.',
    'tab_personal': 'Persönlich',
    'tab_received': 'Empfangen',
    'tab_sent': 'Gesendet',
    'copy_message': 'Nachricht kopieren',
    'destroy_message': 'Nachricht vernichten',
    'node_destruction_title': 'Knotenvernichtung',
    'destroy_message_confirm_body': 'Möchtest du diese Nachricht dauerhaft auf beiden Geräten vernichten?',
    'destroy_button': 'Vernichten',
    'failed_to_send_photo_prefix': 'Foto senden fehlgeschlagen',
    'encrypted_photo_sent_message': '🖼️ Verschlüsseltes Foto gesendet — in Secure Vault Files ansehen',
    'photo_chat_preview': '🖼️ Foto',
    'just_now': 'Gerade eben',
    'failed_to_send_voice_prefix': 'Sprachnachricht senden fehlgeschlagen',
    'voice_message_chat_preview': '🎤 Sprachnachricht',
    'voice_message_label': 'Sprachnachricht',
    'no_secure_channel_error': 'Senden nicht möglich: noch kein sicherer Kanal mit diesem Kontakt ({error}). Versuche, ihn zu entfernen und erneut hinzuzufügen.',
    'block_id_title': 'ID blockieren',
    'block_id_confirm_body': 'Möchtest du diese ID dauerhaft blockieren?',
    'block_button': 'Blockieren',
    'keys_not_available': 'Schlüssel für diesen Kontakt nicht verfügbar.',
    'safety_number_title': 'Sicherheitsnummer',
    'safety_number_desc': 'Führe einen sicheren Anruf mit diesem Kontakt durch und lies diese Nummer laut vor. Stimmt sie auf beiden Geräten überein, hört niemand euer Gespräch mit.',
    'verify_safety_number': 'Sicherheitsnummer prüfen',
    'encrypted_p2p_channel': 'Verschlüsselter P2P-Kanal',
    'destruct_1m': '1 Minute',
    'destruct_5m': '5 Minuten',
    'destruct_1h': '1 Stunde',
    'destruct_24h': '24 Stunden',
    'message_not_decrypted': '[Nachricht nicht entschlüsselt]',
    'call_status_connecting': 'Verbindung wird hergestellt...',
    'call_status_exchanging_keys': 'Verschlüsselungsschlüssel werden ausgetauscht...',
    'call_status_ringing': 'Klingelt...',
    'call_status_connecting_encrypted': 'Verschlüsselter Anruf wird verbunden...',
    'call_status_incoming_encrypted': 'Eingehender verschlüsselter Anruf...',
    'call_status_connected_prefix': 'Verbunden',
    'call_status_connected_encrypted': 'Verbunden und verschlüsselt',
    'call_status_reconnecting': 'Erneut verbinden...',
    'call_contact_unavailable': 'Kontakt nicht verfügbar oder offline.',
    'missed_secure_call': 'Verpasster sicherer Anruf',
    'missed_call_notification_title': 'Verpasster Anruf',
    'setup_code_too_weak': 'Der Entschlüsselungsschlüssel ist zu schwach: verwende mindestens 10 Zeichen und vermeide wiederholte oder fortlaufende Muster.',
    'vault_init_failed_prefix': 'Tresor-Initialisierung fehlgeschlagen',
    'create_vault_title': 'ERSTELLE DEINEN VERSCHLÜSSELTEN TRESOR',
    'create_vault_subtitle': 'Lege deinen Hauptschlüssel fest, um deine\nP2P-kryptografische Identität zu erzeugen',
    'set_decryption_key_label': 'Entschlüsselungsschlüssel festlegen',
    'strength_too_weak': 'Zu schwach',
    'strength_weak': 'Schwach',
    'strength_medium': 'Mittel',
    'strength_strong': 'Stark',
    'strength_very_strong': 'Sehr stark',
    'initialize_vault_button': 'TRESOR INITIALISIEREN',
    'footer_privacy_text': 'Entwickelt mit militärtauglicher Zero-Knowledge-Verschlüsselung.\nAlle Kommunikationen laufen ausschließlich Peer-to-Peer (P2P).\nNachrichten zerstören sich automatisch nach 24 Stunden\ndurch sichere spurenfreie Speicherbereinigung.\nKeine Spuren, keine Protokolle, vollständige Privatsphäre.',
    'vault_not_initialized_device': 'Tresor auf diesem Gerät nicht initialisiert.',
    'invalid_decryption_key': 'Ungültiger Entschlüsselungsschlüssel.',
    'vault_data_corrupted': 'Tresordaten sind beschädigt (Schlüssel war korrekt, aber die Tresordatei selbst ist beschädigt).',
    'decrypt_padlock_title': 'ENTSCHLÜSSLE DEIN PADLOCK',
    'login_subtitle': 'ENTWICKELT MIT MILITÄRTAUGLICHER\nZERO-KNOWLEDGE-VERSCHLÜSSELUNG',
    'enter_decryption_key_label': 'Entschlüsselungsschlüssel eingeben',
    'access_vault_button': 'TRESOR ÖFFNEN',
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
    'language': 'Язык',
    'search_contact_hint': 'Поиск контакта...',
    'encrypted_p2p_contact': 'Зашифрованный P2P-контакт',
    'encrypted_p2p_message_preview': '[Зашифрованное P2P-сообщение]',
    'delete_chat_confirm_title': 'Удалить чат',
    'delete_chat_confirm_body': 'Вы хотите навсегда удалить этот чат?',
    'cancel_button': 'Отмена',
    'delete_button': 'Удалить',
    'settings_header': 'НАСТРОЙКИ',
    'section_core_security': 'Основные протоколы безопасности',
    'info_encryption_title': 'Шифрование военного уровня',
    'info_encryption_desc': 'Стандарт AES-256-GCM и Curve25519.',
    'info_p2p_title': 'Настоящий P2P',
    'info_p2p_desc': 'Прямая передача голоса и данных. Без маршрутизации через сервер.',
    'info_autodestruct_title': 'Криминалистическое самоуничтожение',
    'info_autodestruct_desc': 'Все сообщения уничтожаются максимум за 24 часа.',
    'info_screenshot_title': 'Защита от скриншотов',
    'info_screenshot_desc': 'Съёмка экрана заблокирована во всём приложении для предотвращения утечек данных.',
    'info_timeout_title': 'Безопасный тайм-аут',
    'info_timeout_desc': 'Приложение автоматически закрывается через 15 минут использования для вашей безопасности. Для продолжения потребуется повторный вход. Активные звонки игнорируют это правило для сохранения соединения.',
    'section_premium': 'Padlock Premium',
    'secure_crypto_vault_title': 'Secure Crypto Vault',
    'crypto_vault_desc': 'Хранилище максимальной безопасности для ваших цифровых активов.',
    'section_help_center': 'Центр помощи / Как пользоваться',
    'help_vault_files_q': 'Как использовать Secure Vault Files?',
    'help_vault_files_a': 'Чтобы получить доступ к этому разделу, нужно создать отдельный зашифрованный ключ. Каждый раз при открытии хранилища будет запрашиваться этот ключ, как и при обычном входе в приложение.\n\n• Все фото, сделанные прямо в Padlock, автоматически сохраняются здесь.\n• Документы и фото, отправленные контактами на ваш ID, направляются прямо в это хранилище вместо обычных чатов. Вы получите уведомление об отправке контента, и просмотреть его можно только внутри хранилища.\n• Файлы остаются на 100% зашифрованными и защищёнными, пока их не удалят, экспортируют или отправят повторно вручную.',
    'help_add_contact_q': 'Как добавить контакт?',
    'help_add_contact_a': 'Перейдите на вкладку «Контакты», нажмите синюю кнопку (+) и вставьте ID конфиденциальности или используйте зелёный QR-сканер.',
    'help_share_id_q': 'Как поделиться своим ID?',
    'help_share_id_a': 'Перейдите на вкладку «Профиль». Нажмите «Copy ID», чтобы безопасно вставить его куда угодно, или «QR Code», чтобы кто-то отсканировал ваш экран.',
    'help_rename_contact_q': 'Как переименовать контакт?',
    'help_rename_contact_a': 'На вкладке «Контакты» нажмите значок редактирования (карандаш) рядом с любым контактом, чтобы изменить отображаемое имя.',
    'help_delete_contact_q': 'Как удалить контакт?',
    'help_delete_contact_a': 'На вкладке «Контакты» нажмите и удерживайте контакт. Это навсегда удалит его и уничтожит общие ключи шифрования.',
    'help_wipe_chat_q': 'Как удалить переписку?',
    'help_wipe_chat_a': 'В любом активном чате нажмите меню (три точки) в правом верхнем углу и выберите «Удалить переписку», чтобы уничтожить все сообщения на обоих устройствах.',
    'section_app_preferences': 'Настройки приложения',
    'app_language_title': 'Язык приложения',
    'current_lang_prefix': 'Текущий',
    'silent_mode_desc': 'Отключает все уведомления и звонки.',
    'section_panic_room': 'Комната паники',
    'nuke_vault_title': 'УНИЧТОЖИТЬ ХРАНИЛИЩЕ: СТЕРЕТЬ И УНИЧТОЖИТЬ ВСЁ',
    'nuke_vault_desc': 'Это действие навсегда уничтожит ваш ID конфиденциальности, крипто-средства и все чаты. Оно очищает всё и возвращает вас к экрану активации.',
    'critical_warning_title': 'КРИТИЧЕСКОЕ ПРЕДУПРЕЖДЕНИЕ',
    'nuke_confirm_body': 'Вы уверены, что хотите УНИЧТОЖИТЬ хранилище?\n\n⚠️ ВЫВЕДИТЕ ВСЕ КРИПТО-СРЕДСТВА И СОХРАНИТЕ ФАЙЛЫ ПЕРЕД ПРОДОЛЖЕНИЕМ.\n\nЭто действие необратимо. Приложение будет сброшено до заводского состояния.',
    'nuke_everything_button': 'УНИЧТОЖИТЬ ВСЁ',
    'got_it_button': 'Понятно',
    'edit_name_title': 'Изменить Имя',
    'save_button': 'Сохранить',
    'qr_code_button': 'QR-код',
    'copy_id_button': 'Копировать ID',
    'secure_crypto_vault_short': 'Secure\nCrypto Vault',
    'secure_vault_files_short': 'Secure\nVault Files',
    'privacy_id_label': 'ID конфиденциальности',
    'profile_bio_paragraph': 'Создано с шифрованием Zero-Knowledge военного уровня.\nВсе коммуникации работают строго по принципу P2P (точка-точка).\nСообщения автоматически самоуничтожаются через 24 часа\nс использованием безопасной защиты памяти от отслеживания.\nНи следа, ни логов, полная конфиденциальность.',
    'close_button': 'Закрыть',
    'crypto_code_too_weak': 'Код слишком слабый: используйте не менее 10 символов и избегайте повторяющихся или последовательных шаблонов.',
    'invalid_recovery_phrase': 'Неверная фраза восстановления - проверьте слова и попробуйте снова.',
    'crypto_vault_not_initialized': 'Crypto Vault не инициализирован на этом устройстве.',
    'invalid_crypto_vault_code': 'Неверный код Crypto Vault.',
    'crypto_vault_corrupted': 'Данные Crypto Vault повреждены (код был верным, но сам файл хранилища повреждён).',
    'create_crypto_vault_code_title': 'СОЗДАТЬ КОД CRYPTO VAULT',
    'enter_crypto_vault_code_title': 'ВВЕСТИ КОД CRYPTO VAULT',
    'crypto_code_desc_create': 'Этот код отделён от кодов приложения и Vault Files. Он защищает совершенно новый некастодиальный кошелёк, который контролируете только вы.',
    'crypto_code_desc_enter': 'Введите код Crypto Vault для доступа к кошельку.',
    'create_new_wallet_instead': '← Создать новый кошелёк вместо этого',
    'already_have_recovery_phrase': 'У меня уже есть фраза восстановления (потерян телефон / переустановка)',
    'recovery_phrase_label': 'Ваша фраза восстановления из 12 слов',
    'recovery_phrase_hint': 'слово1 слово2 слово3 ...',
    'set_crypto_vault_code_label': 'Установить код Crypto Vault (для ЭТОГО устройства)',
    'crypto_vault_code_label': 'Код Crypto Vault',
    'restore_wallet_button': 'ВОССТАНОВИТЬ КОШЕЛЁК',
    'create_wallet_button': 'СОЗДАТЬ КОШЕЛЁК',
    'unlock_button': 'РАЗБЛОКИРОВАТЬ',
    'recovery_phrase_title': 'Ваша фраза восстановления',
    'recovery_phrase_warning': '⚠️ Запишите эти 12 слов на бумаге по порядку и храните в надёжном офлайн-месте. Любой, у кого есть эти слова, может украсть ваши средства. Padlock НЕ хранит эту фразу нигде и не может восстановить её за вас.',
    'recovery_phrase_confirm_checkbox': 'Я записал эти слова и надёжно сохранил их офлайн.',
    'continue_button': 'ПРОДОЛЖИТЬ',
    'loading_text': 'Загрузка...',
    'could_not_load_balance': 'Не удалось загрузить баланс',
    'receive_dialog_title': 'Получить',
    'receive_address_warning': 'Сканирование или передача этого кода раскрывает только АДРЕС вашего кошелька - никогда не фразу восстановления.',
    'address_copied_toast': 'Адрес скопирован.',
    'copy_button': 'КОПИРОВАТЬ',
    'testnet_warning': '⚠️ ТЕСТОВАЯ СЕТЬ (Polygon Amoy) - это НЕ реальные средства.',
    'balances_label': 'Балансы',
    'receive_button': 'ПОЛУЧИТЬ',
    'send_button': 'ОТПРАВИТЬ',
    'camera_permission_denied': 'Доступ к камере запрещён. Включите его в настройках телефона > Приложения > Padlock > Разрешения.',
    'scan_wallet_address_title': 'Сканировать Адрес Кошелька',
    'invalid_wallet_address': 'Неверный адрес кошелька.',
    'enter_valid_amount': 'Введите корректную сумму.',
    'price_not_loaded': 'Курс ещё не загружен - попробуйте снова через мгновение.',
    'transaction_sent_title': 'Транзакция Отправлена',
    'done_button': 'ГОТОВО',
    'send_failed_prefix': 'Ошибка отправки',
    'send_title': 'Отправить',
    'recipient_address_label': 'Адрес кошелька получателя',
    'coin_label': 'Монета',
    'amount_in_label': 'Сумма в:',
    'amount_usd_label': 'Сумма (USD)',
    'amount_label_prefix': 'Сумма',
    'loading_price': 'Загрузка курса...',
    'price_label_prefix': 'Курс',
    'confirm_send_button': 'ПОДТВЕРДИТЬ И ОТПРАВИТЬ',
    'vault_files_not_initialized': 'Vault Files не инициализирован на этом устройстве.',
    'invalid_vault_files_code': 'Неверный код Vault Files.',
    'vault_files_corrupted': 'Данные Vault Files повреждены (код был верным, но сам файл хранилища повреждён).',
    'create_vault_files_code_title': 'СОЗДАТЬ КОД VAULT FILES',
    'enter_vault_files_code_title': 'ВВЕДИТЕ КОД VAULT FILES',
    'vault_files_code_desc_create': 'Этот код отличается от кода разблокировки приложения. Тот, кто знает код приложения, НЕ сможет открыть ваши фото и документы без этого кода.',
    'vault_files_code_desc_enter': 'Введите код Vault Files, чтобы просмотреть зашифрованные фото и документы.',
    'set_vault_files_code_label': 'Задать код Vault Files',
    'vault_files_code_label': 'Код Vault Files',
    'create_vault_button': 'СОЗДАТЬ ХРАНИЛИЩЕ',
    'imported_skipped_toast': 'Импортировано: {imported}, пропущено: {skipped} (макс. {mb}МБ каждый).',
    'no_contacts_yet': 'Пока нет контактов.',
    'send_to_title': 'Отправить...',
    'sent_toast': 'Отправлено.',
    'failed_to_send_prefix': 'Не удалось отправить',
    'received_from_prefix': 'Получено от',
    'sent_to_prefix': 'Отправлено',
    'stored_locally_not_sent': 'Сохранено локально — пока никому не отправлено',
    'document_label': 'Документ',
    'document_stored_encrypted_desc': 'Этот документ хранится зашифрованным в Vault Files ({kb} КБ). Используйте «Экспорт», чтобы сохранить его на телефон или поделиться им.',
    'export_button': 'Экспорт',
    'personal_files_empty': 'Пока нет личных файлов.\nИспользуйте кнопку +, чтобы сделать фото или импортировать документ.',
    'received_files_empty': 'Пока ничего не получено.',
    'sent_files_empty': 'Пока ничего не отправлено.',
    'tab_personal': 'Личное',
    'tab_received': 'Полученные',
    'tab_sent': 'Отправленные',
    'copy_message': 'Копировать сообщение',
    'destroy_message': 'Уничтожить сообщение',
    'node_destruction_title': 'Уничтожение узла',
    'destroy_message_confirm_body': 'Уничтожить это сообщение навсегда на обоих устройствах?',
    'destroy_button': 'Уничтожить',
    'failed_to_send_photo_prefix': 'Не удалось отправить фото',
    'encrypted_photo_sent_message': '🖼️ Зашифрованное фото отправлено — смотрите в Secure Vault Files',
    'photo_chat_preview': '🖼️ Фото',
    'just_now': 'Только что',
    'failed_to_send_voice_prefix': 'Не удалось отправить голосовое сообщение',
    'voice_message_chat_preview': '🎤 Голосовое сообщение',
    'voice_message_label': 'Голосовое сообщение',
    'no_secure_channel_error': 'Не удалось отправить: с этим контактом пока нет защищённого канала ({error}). Попробуйте удалить его и добавить снова.',
    'block_id_title': 'Заблокировать ID',
    'block_id_confirm_body': 'Заблокировать этот ID навсегда?',
    'block_button': 'Заблокировать',
    'keys_not_available': 'Ключи для этого контакта недоступны.',
    'safety_number_title': 'Код безопасности',
    'safety_number_desc': 'Совершите защищённый звонок этому контакту и зачитайте этот номер вслух. Если он совпадает на обоих устройствах, никто не перехватывает ваш разговор.',
    'verify_safety_number': 'Проверить код безопасности',
    'encrypted_p2p_channel': 'Зашифрованный P2P-канал',
    'destruct_1m': '1 минута',
    'destruct_5m': '5 минут',
    'destruct_1h': '1 час',
    'destruct_24h': '24 часа',
    'message_not_decrypted': '[Сообщение не расшифровано]',
    'call_status_connecting': 'Соединение...',
    'call_status_exchanging_keys': 'Обмен ключами шифрования...',
    'call_status_ringing': 'Звонок...',
    'call_status_connecting_encrypted': 'Установка защищённого вызова...',
    'call_status_incoming_encrypted': 'Входящий защищённый вызов...',
    'call_status_connected_prefix': 'Соединено',
    'call_status_connected_encrypted': 'Соединено и зашифровано',
    'call_status_reconnecting': 'Переподключение...',
    'call_contact_unavailable': 'Контакт недоступен или не в сети.',
    'missed_secure_call': 'Пропущенный защищённый звонок',
    'missed_call_notification_title': 'Пропущенный звонок',
    'setup_code_too_weak': 'Ключ расшифровки слишком слабый: используйте минимум 10 символов и избегайте повторяющихся или последовательных шаблонов.',
    'vault_init_failed_prefix': 'Не удалось инициализировать хранилище',
    'create_vault_title': 'СОЗДАЙТЕ СВОЁ ЗАШИФРОВАННОЕ ХРАНИЛИЩЕ',
    'create_vault_subtitle': 'Задайте главный ключ для создания\nвашей криптографической P2P-личности',
    'set_decryption_key_label': 'Задать ключ расшифровки',
    'strength_too_weak': 'Слишком слабый',
    'strength_weak': 'Слабый',
    'strength_medium': 'Средний',
    'strength_strong': 'Сильный',
    'strength_very_strong': 'Очень сильный',
    'initialize_vault_button': 'ИНИЦИАЛИЗИРОВАТЬ ХРАНИЛИЩЕ',
    'footer_privacy_text': 'Разработано с шифрованием Zero-Knowledge военного уровня.\nВся связь осуществляется строго напрямую (P2P).\nСообщения автоматически самоуничтожаются через 24 часа\nс безопасной очисткой памяти от следов.\nНоль следов, ноль журналов, полная приватность.',
    'vault_not_initialized_device': 'Хранилище не инициализировано на этом устройстве.',
    'invalid_decryption_key': 'Неверный ключ расшифровки.',
    'vault_data_corrupted': 'Данные хранилища повреждены (ключ был верным, но сам файл хранилища повреждён).',
    'decrypt_padlock_title': 'РАСШИФРУЙТЕ СВОЙ PADLOCK',
    'login_subtitle': 'РАЗРАБОТАНО С ШИФРОВАНИЕМ ZERO-KNOWLEDGE\nВОЕННОГО УРОВНЯ',
    'enter_decryption_key_label': 'Введите ключ расшифровки',
    'access_vault_button': 'ОТКРЫТЬ ХРАНИЛИЩЕ',
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
    'language': 'Мова',
    'search_contact_hint': 'Пошук контакту...',
    'encrypted_p2p_contact': 'Зашифрований P2P-контакт',
    'encrypted_p2p_message_preview': '[Зашифроване P2P-повідомлення]',
    'delete_chat_confirm_title': 'Видалити чат',
    'delete_chat_confirm_body': 'Ви хочете назавжди видалити цей чат?',
    'cancel_button': 'Скасувати',
    'delete_button': 'Видалити',
    'settings_header': 'НАЛАШТУВАННЯ',
    'section_core_security': 'Основні протоколи безпеки',
    'info_encryption_title': 'Шифрування військового рівня',
    'info_encryption_desc': 'Стандарт AES-256-GCM і Curve25519.',
    'info_p2p_title': 'Справжній P2P',
    'info_p2p_desc': 'Пряма передача голосу й даних. Без маршрутизації через сервер.',
    'info_autodestruct_title': 'Криміналістичне самознищення',
    'info_autodestruct_desc': 'Усі повідомлення знищуються максимум за 24 години.',
    'info_screenshot_title': 'Захист від знімків екрана',
    'info_screenshot_desc': 'Знімки екрана заблоковано в усьому додатку, щоб запобігти витоку даних.',
    'info_timeout_title': 'Безпечний тайм-аут',
    'info_timeout_desc': 'Додаток автоматично закривається через 15 хвилин використання для вашої безпеки. Для продовження потрібен повторний вхід. Активні дзвінки ігнорують це правило, щоб зберегти з\'єднання.',
    'section_premium': 'Padlock Premium',
    'secure_crypto_vault_title': 'Secure Crypto Vault',
    'crypto_vault_desc': 'Сховище максимальної безпеки для ваших цифрових активів.',
    'section_help_center': 'Центр допомоги / Як користуватися',
    'help_vault_files_q': 'Як використовувати Secure Vault Files?',
    'help_vault_files_a': 'Щоб отримати доступ до цього розділу, потрібно створити окремий зашифрований ключ. Кожного разу, коли ви відкриваєте сховище, буде запитуватися цей ключ для входу, так само як звичайний вхід у додаток.\n\n• Усі фото, зроблені прямо в Padlock, автоматично зберігаються тут.\n• Документи та фото, надіслані контактами на ваш ID, спрямовуються прямо в це сховище замість звичайних чатів. Ви отримаєте сповіщення про надісланий контент, і переглянути його можна лише всередині сховища.\n• Файли залишаються на 100% зашифрованими та захищеними, доки їх не видалять, експортують або надішлють повторно вручну.',
    'help_add_contact_q': 'Як додати контакт?',
    'help_add_contact_a': 'Перейдіть на вкладку «Контакти», натисніть синю кнопку (+) і вставте ID приватності або скористайтеся зеленим QR-сканером.',
    'help_share_id_q': 'Як поділитися своїм ID?',
    'help_share_id_a': 'Перейдіть на вкладку «Профіль». Натисніть «Copy ID», щоб безпечно вставити його будь-де, або «QR Code», щоб хтось відсканував ваш екран.',
    'help_rename_contact_q': 'Як перейменувати контакт?',
    'help_rename_contact_a': 'На вкладці «Контакти» натисніть значок редагування (олівець) поруч із будь-яким контактом, щоб змінити відображуване ім\'я.',
    'help_delete_contact_q': 'Як видалити контакт?',
    'help_delete_contact_a': 'На вкладці «Контакти» натисніть і утримуйте контакт. Це назавжди видалить його та знищить спільні ключі шифрування.',
    'help_wipe_chat_q': 'Як видалити розмову?',
    'help_wipe_chat_a': 'У будь-якому активному чаті натисніть меню (три крапки) у верхньому правому куті та виберіть «Видалити розмову», щоб знищити всі повідомлення на обох пристроях.',
    'section_app_preferences': 'Налаштування додатку',
    'app_language_title': 'Мова додатку',
    'current_lang_prefix': 'Поточна',
    'silent_mode_desc': 'Вимикає всі сповіщення та дзвінки.',
    'section_panic_room': 'Кімната паніки',
    'nuke_vault_title': 'ЗНИЩИТИ СХОВИЩЕ: ОЧИСТИТИ ТА ЗНИЩИТИ ВСЕ',
    'nuke_vault_desc': 'Ця дія назавжди знищить ваш ID приватності, криптокошти та всі чати. Вона очищає все і повертає вас до екрана активації.',
    'critical_warning_title': 'КРИТИЧНЕ ПОПЕРЕДЖЕННЯ',
    'nuke_confirm_body': 'Ви впевнені, що хочете ЗНИЩИТИ сховище?\n\n⚠️ ВИВЕДІТЬ УСІ КРИПТОКОШТИ ТА ЗБЕРЕЖІТЬ ФАЙЛИ ПЕРЕД ПРОДОВЖЕННЯМ.\n\nЦя дія незворотна. Додаток буде скинуто до заводського стану.',
    'nuke_everything_button': 'ЗНИЩИТИ ВСЕ',
    'got_it_button': 'Зрозуміло',
    'edit_name_title': 'Змінити Ім\'я',
    'save_button': 'Зберегти',
    'qr_code_button': 'QR-код',
    'copy_id_button': 'Копіювати ID',
    'secure_crypto_vault_short': 'Secure\nCrypto Vault',
    'secure_vault_files_short': 'Secure\nVault Files',
    'privacy_id_label': 'ID конфіденційності',
    'profile_bio_paragraph': 'Створено з шифруванням Zero-Knowledge військового рівня.\nУсі комунікації працюють строго за принципом P2P (точка-точка).\nПовідомлення автоматично самознищуються через 24 години\nіз використанням безпечного захисту пам\'яті від відстеження.\nЖодного сліду, жодних журналів, повна конфіденційність.',
    'close_button': 'Закрити',
    'crypto_code_too_weak': 'Код надто слабкий: використовуйте щонайменше 10 символів і уникайте повторюваних чи послідовних шаблонів.',
    'invalid_recovery_phrase': 'Невірна фраза відновлення - перевірте слова і спробуйте ще раз.',
    'crypto_vault_not_initialized': 'Crypto Vault не ініціалізовано на цьому пристрої.',
    'invalid_crypto_vault_code': 'Невірний код Crypto Vault.',
    'crypto_vault_corrupted': 'Дані Crypto Vault пошкоджені (код був правильний, але сам файл сховища пошкоджено).',
    'create_crypto_vault_code_title': 'СТВОРИТИ КОД CRYPTO VAULT',
    'enter_crypto_vault_code_title': 'ВВЕСТИ КОД CRYPTO VAULT',
    'crypto_code_desc_create': 'Цей код відокремлений від кодів додатку та Vault Files. Він захищає абсолютно новий некастодіальний гаманець, який контролюєте лише ви.',
    'crypto_code_desc_enter': 'Введіть код Crypto Vault для доступу до гаманця.',
    'create_new_wallet_instead': '← Створити новий гаманець замість цього',
    'already_have_recovery_phrase': 'У мене вже є фраза відновлення (втрачено телефон / перевстановлення)',
    'recovery_phrase_label': 'Ваша фраза відновлення з 12 слів',
    'recovery_phrase_hint': 'слово1 слово2 слово3 ...',
    'set_crypto_vault_code_label': 'Встановити код Crypto Vault (для ЦЬОГО пристрою)',
    'crypto_vault_code_label': 'Код Crypto Vault',
    'restore_wallet_button': 'ВІДНОВИТИ ГАМАНЕЦЬ',
    'create_wallet_button': 'СТВОРИТИ ГАМАНЕЦЬ',
    'unlock_button': 'РОЗБЛОКУВАТИ',
    'recovery_phrase_title': 'Ваша Фраза Відновлення',
    'recovery_phrase_warning': '⚠️ Запишіть ці 12 слів на папері по порядку і зберігайте в надійному офлайн-місці. Будь-хто з цими словами може викрасти ваші кошти. Padlock НЕ зберігає цю фразу ніде і не може відновити її за вас.',
    'recovery_phrase_confirm_checkbox': 'Я записав ці слова і надійно зберіг їх офлайн.',
    'continue_button': 'ПРОДОВЖИТИ',
    'loading_text': 'Завантаження...',
    'could_not_load_balance': 'Не вдалося завантажити баланс',
    'receive_dialog_title': 'Отримати',
    'receive_address_warning': 'Сканування або передача цього коду розкриває лише АДРЕСУ вашого гаманця - ніколи не фразу відновлення.',
    'address_copied_toast': 'Адресу скопійовано.',
    'copy_button': 'КОПІЮВАТИ',
    'testnet_warning': '⚠️ ТЕСТОВА МЕРЕЖА (Polygon Amoy) - це НЕ реальні кошти.',
    'balances_label': 'Баланси',
    'receive_button': 'ОТРИМАТИ',
    'send_button': 'НАДІСЛАТИ',
    'camera_permission_denied': 'Доступ до камери заборонено. Увімкніть його в налаштуваннях телефону > Додатки > Padlock > Дозволи.',
    'scan_wallet_address_title': 'Сканувати Адресу Гаманця',
    'invalid_wallet_address': 'Невірна адреса гаманця.',
    'enter_valid_amount': 'Введіть коректну суму.',
    'price_not_loaded': 'Курс ще не завантажено - спробуйте ще раз за мить.',
    'transaction_sent_title': 'Транзакцію Надіслано',
    'done_button': 'ГОТОВО',
    'send_failed_prefix': 'Помилка надсилання',
    'send_title': 'Надіслати',
    'recipient_address_label': 'Адреса гаманця отримувача',
    'coin_label': 'Монета',
    'amount_in_label': 'Сума в:',
    'amount_usd_label': 'Сума (USD)',
    'amount_label_prefix': 'Сума',
    'loading_price': 'Завантаження курсу...',
    'price_label_prefix': 'Курс',
    'confirm_send_button': 'ПІДТВЕРДИТИ Й НАДІСЛАТИ',
    'vault_files_not_initialized': 'Vault Files не ініціалізовано на цьому пристрої.',
    'invalid_vault_files_code': 'Невірний код Vault Files.',
    'vault_files_corrupted': 'Дані Vault Files пошкоджені (код був правильним, але сам файл сховища пошкоджено).',
    'create_vault_files_code_title': 'СТВОРИТИ КОД VAULT FILES',
    'enter_vault_files_code_title': 'ВВЕДІТЬ КОД VAULT FILES',
    'vault_files_code_desc_create': 'Цей код відрізняється від коду розблокування застосунку. Той, хто знає код застосунку, НЕ зможе відкрити ваші фото й документи без цього коду.',
    'vault_files_code_desc_enter': 'Введіть код Vault Files, щоб переглянути зашифровані фото й документи.',
    'set_vault_files_code_label': 'Встановити код Vault Files',
    'vault_files_code_label': 'Код Vault Files',
    'create_vault_button': 'СТВОРИТИ СХОВИЩЕ',
    'imported_skipped_toast': 'Імпортовано: {imported}, пропущено: {skipped} (макс. {mb}МБ кожен).',
    'no_contacts_yet': 'Ще немає контактів.',
    'send_to_title': 'Надіслати...',
    'sent_toast': 'Надіслано.',
    'failed_to_send_prefix': 'Не вдалося надіслати',
    'received_from_prefix': 'Отримано від',
    'sent_to_prefix': 'Надіслано до',
    'stored_locally_not_sent': 'Збережено локально — ще нікому не надіслано',
    'document_label': 'Документ',
    'document_stored_encrypted_desc': 'Цей документ зберігається зашифрованим у Vault Files ({kb} КБ). Використайте «Експорт», щоб зберегти його на телефон або поділитися ним.',
    'export_button': 'Експорт',
    'personal_files_empty': 'Ще немає особистих файлів.\nВикористайте кнопку +, щоб зробити фото або імпортувати документ.',
    'received_files_empty': 'Поки що нічого не отримано.',
    'sent_files_empty': 'Поки що нічого не надіслано.',
    'tab_personal': 'Особисте',
    'tab_received': 'Отримані',
    'tab_sent': 'Надіслані',
    'copy_message': 'Копіювати повідомлення',
    'destroy_message': 'Знищити повідомлення',
    'node_destruction_title': 'Знищення вузла',
    'destroy_message_confirm_body': 'Знищити це повідомлення назавжди на обох пристроях?',
    'destroy_button': 'Знищити',
    'failed_to_send_photo_prefix': 'Не вдалося надіслати фото',
    'encrypted_photo_sent_message': '🖼️ Зашифроване фото надіслано — перегляньте в Secure Vault Files',
    'photo_chat_preview': '🖼️ Фото',
    'just_now': 'Щойно',
    'failed_to_send_voice_prefix': 'Не вдалося надіслати голосове повідомлення',
    'voice_message_chat_preview': '🎤 Голосове повідомлення',
    'voice_message_label': 'Голосове повідомлення',
    'no_secure_channel_error': 'Не вдалося надіслати: з цим контактом ще немає захищеного каналу ({error}). Спробуйте видалити його та додати знову.',
    'block_id_title': 'Заблокувати ID',
    'block_id_confirm_body': 'Заблокувати цей ID назавжди?',
    'block_button': 'Заблокувати',
    'keys_not_available': 'Ключі для цього контакту недоступні.',
    'safety_number_title': 'Код безпеки',
    'safety_number_desc': 'Здійсніть захищений виклик цьому контакту та прочитайте це число вголос. Якщо воно збігається на обох пристроях, ніхто не перехоплює вашу розмову.',
    'verify_safety_number': 'Перевірити код безпеки',
    'encrypted_p2p_channel': 'Зашифрований P2P-канал',
    'destruct_1m': '1 хвилина',
    'destruct_5m': '5 хвилин',
    'destruct_1h': '1 година',
    'destruct_24h': '24 години',
    'message_not_decrypted': '[Повідомлення не розшифровано]',
    'call_status_connecting': 'З\'єднання...',
    'call_status_exchanging_keys': 'Обмін ключами шифрування...',
    'call_status_ringing': 'Дзвінок...',
    'call_status_connecting_encrypted': 'Встановлення захищеного виклику...',
    'call_status_incoming_encrypted': 'Вхідний захищений виклик...',
    'call_status_connected_prefix': 'З\'єднано',
    'call_status_connected_encrypted': 'З\'єднано й зашифровано',
    'call_status_reconnecting': 'Повторне з\'єднання...',
    'call_contact_unavailable': 'Контакт недоступний або офлайн.',
    'missed_secure_call': 'Пропущений захищений виклик',
    'missed_call_notification_title': 'Пропущений виклик',
    'setup_code_too_weak': 'Ключ розшифрування занадто слабкий: використовуйте щонайменше 10 символів і уникайте повторюваних або послідовних шаблонів.',
    'vault_init_failed_prefix': 'Не вдалося ініціалізувати сховище',
    'create_vault_title': 'СТВОРІТЬ СВОЄ ЗАШИФРОВАНЕ СХОВИЩЕ',
    'create_vault_subtitle': 'Встановіть головний ключ для створення\nвашої криптографічної P2P-ідентичності',
    'set_decryption_key_label': 'Встановити ключ розшифрування',
    'strength_too_weak': 'Занадто слабкий',
    'strength_weak': 'Слабкий',
    'strength_medium': 'Середній',
    'strength_strong': 'Сильний',
    'strength_very_strong': 'Дуже сильний',
    'initialize_vault_button': 'ІНІЦІАЛІЗУВАТИ СХОВИЩЕ',
    'footer_privacy_text': 'Розроблено з шифруванням Zero-Knowledge військового рівня.\nВесь зв\'язок здійснюється виключно напряму (P2P).\nПовідомлення автоматично самознищуються через 24 години\nіз безпечним очищенням пам\'яті від слідів.\nНуль слідів, нуль журналів, повна приватність.',
    'vault_not_initialized_device': 'Сховище не ініціалізовано на цьому пристрої.',
    'invalid_decryption_key': 'Невірний ключ розшифрування.',
    'vault_data_corrupted': 'Дані сховища пошкоджені (ключ був правильним, але сам файл сховища пошкоджено).',
    'decrypt_padlock_title': 'РОЗШИФРУЙТЕ СВІЙ PADLOCK',
    'login_subtitle': 'РОЗРОБЛЕНО З ШИФРУВАННЯМ ZERO-KNOWLEDGE\nВІЙСЬКОВОГО РІВНЯ',
    'enter_decryption_key_label': 'Введіть ключ розшифрування',
    'access_vault_button': 'ВІДКРИТИ СХОВИЩЕ',
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
    'language': '语言',
    'search_contact_hint': '搜索联系人...',
    'encrypted_p2p_contact': '加密的点对点联系人',
    'encrypted_p2p_message_preview': '[加密点对点消息]',
    'delete_chat_confirm_title': '删除对话',
    'delete_chat_confirm_body': '您确定要永久删除此对话吗？',
    'cancel_button': '取消',
    'delete_button': '删除',
    'settings_header': '设置',
    'section_core_security': '核心安全协议',
    'info_encryption_title': '军事级加密',
    'info_encryption_desc': 'AES-256-GCM 和 Curve25519 标准。',
    'info_p2p_title': '真正的点对点',
    'info_p2p_desc': '直接语音和数据传输，零服务器路由。',
    'info_autodestruct_title': '取证级自动销毁',
    'info_autodestruct_desc': '所有消息最多在 24 小时内销毁。',
    'info_screenshot_title': '截图保护',
    'info_screenshot_desc': '整个应用全局阻止屏幕截图，以防止未经授权的数据泄露。',
    'info_timeout_title': '安全超时',
    'info_timeout_desc': '为了您的安全，应用使用 15 分钟后会自动关闭。需要重新登录才能继续。通话进行中不受此规则限制，以保持连接。',
    'section_premium': 'Padlock Premium',
    'secure_crypto_vault_title': 'Secure Crypto Vault',
    'crypto_vault_desc': '为您的数字资产提供最高安全级别的存储。',
    'section_help_center': '帮助中心 / 使用方法',
    'help_vault_files_q': '如何使用 Secure Vault Files？',
    'help_vault_files_a': '要访问此部分，您必须创建一个专用的加密密钥。每次打开保险库时，都会要求您输入此密钥登录，方式与应用安全登录相同。\n\n• 直接在 Padlock 内拍摄的所有照片都会自动保存在这里。\n• 联系人发送到您 ID 的文档和照片会直接进入此保险库，而不是普通聊天。您会收到已发送媒体的通知提醒，必须在保险库内查看。\n• 文件在手动删除、导出或重新发送之前将保持 100% 加密和安全。',
    'help_add_contact_q': '如何添加联系人？',
    'help_add_contact_a': '前往"联系人"标签页，点击蓝色 (+) 按钮，然后粘贴隐私 ID 或使用绿色二维码扫描器。',
    'help_share_id_q': '如何分享我的 ID？',
    'help_share_id_a': '前往"个人资料"标签页。点击"Copy ID"可安全地将其粘贴到任何地方，或点击"QR Code"让他人扫描您的屏幕。',
    'help_rename_contact_q': '如何重命名联系人？',
    'help_rename_contact_a': '在"联系人"标签页中，点击任意联系人旁的编辑（铅笔）图标以更改其显示名称。',
    'help_delete_contact_q': '如何删除联系人？',
    'help_delete_contact_a': '在"联系人"标签页中，长按任意联系人。这将永久删除该联系人并销毁共享的加密密钥。',
    'help_wipe_chat_q': '如何清除对话？',
    'help_wipe_chat_a': '在任何活跃对话中，点击右上角的菜单（三个点）并选择"清除对话"，以销毁双方设备上的所有消息。',
    'section_app_preferences': '应用偏好设置',
    'app_language_title': '应用语言',
    'current_lang_prefix': '当前',
    'silent_mode_desc': '静音所有通知和来电铃声。',
    'section_panic_room': '紧急清除室',
    'nuke_vault_title': '清除保险库：清除并销毁所有内容',
    'nuke_vault_desc': '此操作将永久销毁您的隐私 ID、加密货币资金和所有聊天记录。它会清除所有内容并将您带回激活屏幕。',
    'critical_warning_title': '重要警告',
    'nuke_confirm_body': '您确定要清除保险库吗？\n\n⚠️ 请在继续之前提取所有加密货币资金并保存您的文件。\n\n此操作不可逆转。应用程序将被重置为出厂状态。',
    'nuke_everything_button': '清除所有内容',
    'got_it_button': '知道了',
    'edit_name_title': '编辑姓名',
    'save_button': '保存',
    'qr_code_button': '二维码',
    'copy_id_button': '复制 ID',
    'secure_crypto_vault_short': 'Secure\nCrypto Vault',
    'secure_vault_files_short': 'Secure\nVault Files',
    'privacy_id_label': '隐私 ID',
    'profile_bio_paragraph': '采用军事级零知识加密技术打造。\n所有通信严格采用点对点（P2P）方式运行。\n消息在 24 小时后使用安全的反追踪内存清理技术自动销毁。\n零痕迹，零日志，完全隐私。',
    'close_button': '关闭',
    'crypto_code_too_weak': '密码太弱：请至少使用 10 个字符，并避免重复或连续的模式。',
    'invalid_recovery_phrase': '恢复短语无效 - 请检查单词并重试。',
    'crypto_vault_not_initialized': '此设备上尚未初始化 Crypto Vault。',
    'invalid_crypto_vault_code': 'Crypto Vault 密码无效。',
    'crypto_vault_corrupted': 'Crypto Vault 数据已损坏（密码正确，但保险库文件本身已损坏）。',
    'create_crypto_vault_code_title': '创建 CRYPTO VAULT 密码',
    'enter_crypto_vault_code_title': '输入 CRYPTO VAULT 密码',
    'crypto_code_desc_create': '此密码与应用和 Vault Files 密码是分开的。它保护一个全新的、非托管的、只有您能控制的钱包。',
    'crypto_code_desc_enter': '输入您的 Crypto Vault 密码以访问您的钱包。',
    'create_new_wallet_instead': '← 改为创建新钱包',
    'already_have_recovery_phrase': '我已经有恢复短语（手机丢失/重新安装）',
    'recovery_phrase_label': '您的 12 个单词恢复短语',
    'recovery_phrase_hint': '单词1 单词2 单词3 ...',
    'set_crypto_vault_code_label': '设置 Crypto Vault 密码（用于此设备）',
    'crypto_vault_code_label': 'Crypto Vault 密码',
    'restore_wallet_button': '恢复钱包',
    'create_wallet_button': '创建钱包',
    'unlock_button': '解锁',
    'recovery_phrase_title': '您的恢复短语',
    'recovery_phrase_warning': '⚠️ 请按顺序将这 12 个单词写在纸上，并妥善保存在安全的离线地方。任何拥有这些单词的人都可以窃取您的资金。Padlock 不会在任何地方存储此短语，也无法为您恢复它。',
    'recovery_phrase_confirm_checkbox': '我已写下这些单词并安全地离线保存。',
    'continue_button': '继续',
    'loading_text': '加载中...',
    'could_not_load_balance': '无法加载余额',
    'receive_dialog_title': '接收',
    'receive_address_warning': '扫描或分享此代码只会透露您钱包的地址 - 绝不会透露您的恢复短语。',
    'address_copied_toast': '地址已复制。',
    'copy_button': '复制',
    'testnet_warning': '⚠️ 测试网络（Polygon Amoy）- 这不是真实资金。',
    'balances_label': '余额',
    'receive_button': '接收',
    'send_button': '发送',
    'camera_permission_denied': '相机权限被拒绝。请在手机设置 > 应用 > Padlock > 权限中启用。',
    'scan_wallet_address_title': '扫描钱包地址',
    'invalid_wallet_address': '钱包地址无效。',
    'enter_valid_amount': '请输入有效金额。',
    'price_not_loaded': '价格尚未加载 - 请稍后再试。',
    'transaction_sent_title': '交易已发送',
    'done_button': '完成',
    'send_failed_prefix': '发送失败',
    'send_title': '发送',
    'recipient_address_label': '收款人钱包地址',
    'coin_label': '币种',
    'amount_in_label': '金额单位：',
    'amount_usd_label': '金额（美元）',
    'amount_label_prefix': '金额',
    'loading_price': '正在加载价格...',
    'price_label_prefix': '价格',
    'confirm_send_button': '确认并发送',
    'vault_files_not_initialized': '此设备尚未初始化 Vault Files。',
    'invalid_vault_files_code': 'Vault Files 代码无效。',
    'vault_files_corrupted': 'Vault Files 数据已损坏(代码正确,但保险库文件本身已损坏)。',
    'create_vault_files_code_title': '创建 VAULT FILES 代码',
    'enter_vault_files_code_title': '输入 VAULT FILES 代码',
    'vault_files_code_desc_create': '此代码与您的应用解锁代码不同。知道应用代码的人如果没有此代码,将无法打开您的照片和文档。',
    'vault_files_code_desc_enter': '输入您的 Vault Files 代码以查看加密的照片和文档。',
    'set_vault_files_code_label': '设置 Vault Files 代码',
    'vault_files_code_label': 'Vault Files 代码',
    'create_vault_button': '创建保险库',
    'imported_skipped_toast': '已导入 {imported} 个,跳过 {skipped} 个(每个最大 {mb}MB)。',
    'no_contacts_yet': '还没有联系人。',
    'send_to_title': '发送给...',
    'sent_toast': '已发送。',
    'failed_to_send_prefix': '发送失败',
    'received_from_prefix': '收自',
    'sent_to_prefix': '已发送给',
    'stored_locally_not_sent': '仅本地保存 — 尚未发送给任何人',
    'document_label': '文档',
    'document_stored_encrypted_desc': '此文档以加密方式保存在您的 Vault Files 中({kb} KB)。使用导出可将其保存回手机或分享。',
    'export_button': '导出',
    'personal_files_empty': '还没有个人文件。\n使用 + 按钮拍照或导入文档。',
    'received_files_empty': '还没有收到任何内容。',
    'sent_files_empty': '还没有发送任何内容。',
    'tab_personal': '个人',
    'tab_received': '已接收',
    'tab_sent': '已发送',
    'copy_message': '复制消息',
    'destroy_message': '销毁消息',
    'node_destruction_title': '节点销毁',
    'destroy_message_confirm_body': '要在两台设备上永久销毁此消息吗?',
    'destroy_button': '销毁',
    'failed_to_send_photo_prefix': '发送照片失败',
    'encrypted_photo_sent_message': '🖼️ 已发送加密照片 — 在 Secure Vault Files 中查看',
    'photo_chat_preview': '🖼️ 照片',
    'just_now': '刚刚',
    'failed_to_send_voice_prefix': '发送语音消息失败',
    'voice_message_chat_preview': '🎤 语音消息',
    'voice_message_label': '语音消息',
    'no_secure_channel_error': '无法发送:与该联系人尚无安全通道({error})。请尝试删除后重新添加。',
    'block_id_title': '屏蔽 ID',
    'block_id_confirm_body': '要永久屏蔽此 ID 吗?',
    'block_button': '屏蔽',
    'keys_not_available': '该联系人的密钥不可用。',
    'safety_number_title': '安全码',
    'safety_number_desc': '与该联系人进行一次安全通话,并大声读出此号码。如果两台设备上的号码一致,说明没有人在窃听你们的对话。',
    'verify_safety_number': '验证安全码',
    'encrypted_p2p_channel': '加密的 P2P 通道',
    'destruct_1m': '1 分钟',
    'destruct_5m': '5 分钟',
    'destruct_1h': '1 小时',
    'destruct_24h': '24 小时',
    'message_not_decrypted': '[消息未解密]',
    'call_status_connecting': '连接中...',
    'call_status_exchanging_keys': '正在交换加密密钥...',
    'call_status_ringing': '响铃中...',
    'call_status_connecting_encrypted': '正在建立加密通话...',
    'call_status_incoming_encrypted': '来电加密通话...',
    'call_status_connected_prefix': '已连接',
    'call_status_connected_encrypted': '已连接并加密',
    'call_status_reconnecting': '重新连接中...',
    'call_contact_unavailable': '联系人不可用或离线。',
    'missed_secure_call': '未接安全通话',
    'missed_call_notification_title': '未接来电',
    'setup_code_too_weak': '解密密钥太弱:请使用至少 10 个字符,并避免重复或连续的模式。',
    'vault_init_failed_prefix': '保险库初始化失败',
    'create_vault_title': '创建您的加密保险库',
    'create_vault_subtitle': '设置您的主密钥以生成\nP2P 加密身份',
    'set_decryption_key_label': '设置解密密钥',
    'strength_too_weak': '太弱',
    'strength_weak': '弱',
    'strength_medium': '中等',
    'strength_strong': '强',
    'strength_very_strong': '非常强',
    'initialize_vault_button': '初始化保险库',
    'footer_privacy_text': '采用军用级零知识加密技术打造。\n所有通信均严格采用点对点(P2P)方式运行。\n消息将在 24 小时后使用安全的反追踪内存清理技术自动销毁。\n零痕迹,零日志,完全隐私。',
    'vault_not_initialized_device': '此设备上的保险库尚未初始化。',
    'invalid_decryption_key': '解密密钥无效。',
    'vault_data_corrupted': '保险库数据已损坏(密钥正确,但保险库文件本身已损坏)。',
    'decrypt_padlock_title': '解密您的 PADLOCK',
    'login_subtitle': '采用军用级零知识加密技术打造',
    'enter_decryption_key_label': '输入解密密钥',
    'access_vault_button': '进入保险库',
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
    'language': '언어',
    'search_contact_hint': '연락처 검색...',
    'encrypted_p2p_contact': '암호화된 P2P 연락처',
    'encrypted_p2p_message_preview': '[암호화된 P2P 메시지]',
    'delete_chat_confirm_title': '대화 삭제',
    'delete_chat_confirm_body': '이 대화를 영구적으로 삭제하시겠습니까?',
    'cancel_button': '취소',
    'delete_button': '삭제',
    'settings_header': '설정',
    'section_core_security': '핵심 보안 프로토콜',
    'info_encryption_title': '군사급 암호화',
    'info_encryption_desc': 'AES-256-GCM 및 Curve25519 표준.',
    'info_p2p_title': '진정한 P2P',
    'info_p2p_desc': '직접 음성 및 데이터 전송. 서버 라우팅 없음.',
    'info_autodestruct_title': '포렌식 자동 삭제',
    'info_autodestruct_desc': '모든 메시지는 최대 24시간 이내에 파기됩니다.',
    'info_screenshot_title': '스크린샷 보호',
    'info_screenshot_desc': '무단 데이터 유출을 방지하기 위해 앱 전체에서 화면 캡처가 전역적으로 차단됩니다.',
    'info_timeout_title': '안전 시간 초과',
    'info_timeout_desc': '보안을 위해 15분 사용 후 앱이 자동으로 종료됩니다. 계속하려면 다시 로그인해야 합니다. 활성 통화는 연결 유지를 위해 이 규칙을 무시합니다.',
    'section_premium': 'Padlock Premium',
    'secure_crypto_vault_title': 'Secure Crypto Vault',
    'crypto_vault_desc': '디지털 자산을 위한 최고 보안 저장소.',
    'section_help_center': '도움말 센터 / 사용 방법',
    'help_vault_files_q': 'Secure Vault Files 사용 방법은?',
    'help_vault_files_a': '이 섹션에 접근하려면 전용 암호화 키를 생성해야 합니다. 보관함을 열 때마다 앱 보안 로그인과 마찬가지로 이 키를 입력하라는 메시지가 표시됩니다.\n\n• Padlock 내에서 직접 찍은 모든 사진은 자동으로 여기에 저장됩니다.\n• 연락처가 회원님의 ID로 보낸 문서와 사진은 일반 채팅 대신 이 보관함으로 바로 전달됩니다. 미디어가 전송되었다는 알림을 받게 되며, 보관함 내에서 확인해야 합니다.\n• 파일은 수동으로 삭제, 내보내기 또는 재전송할 때까지 100% 암호화되어 안전하게 유지됩니다.',
    'help_add_contact_q': '연락처를 추가하는 방법은?',
    'help_add_contact_a': '"연락처" 탭으로 이동하여 파란색 (+) 버튼을 누르고 개인정보 ID를 붙여넣거나 녹색 QR 스캐너를 사용하세요.',
    'help_share_id_q': '내 ID를 공유하는 방법은?',
    'help_share_id_a': '"프로필" 탭으로 이동하세요. "Copy ID"를 눌러 어디에나 안전하게 붙여넣거나, "QR Code"를 눌러 다른 사람이 화면을 스캔하게 하세요.',
    'help_rename_contact_q': '연락처 이름을 바꾸는 방법은?',
    'help_rename_contact_a': '"연락처" 탭에서 연락처 옆의 편집(연필) 아이콘을 눌러 표시 이름을 변경하세요.',
    'help_delete_contact_q': '연락처를 삭제하는 방법은?',
    'help_delete_contact_a': '"연락처" 탭에서 연락처를 길게 누르세요. 이렇게 하면 영구적으로 삭제되고 공유 암호화 키가 파기됩니다.',
    'help_wipe_chat_q': '대화를 삭제하는 방법은?',
    'help_wipe_chat_a': '활성 채팅 내에서 오른쪽 상단의 메뉴(점 세 개)를 누르고 "대화 삭제"를 선택하여 양쪽 기기의 모든 메시지를 파기하세요.',
    'section_app_preferences': '앱 환경설정',
    'app_language_title': '앱 언어',
    'current_lang_prefix': '현재',
    'silent_mode_desc': '모든 알림과 통화 벨소리를 음소거합니다.',
    'section_panic_room': '패닉룸',
    'nuke_vault_title': '보관함 초기화: 모두 삭제 및 파기',
    'nuke_vault_desc': '이 작업은 개인정보 ID, 암호화폐 자금 및 모든 채팅을 영구적으로 파기합니다. 모든 것을 지우고 활성화 화면으로 돌아갑니다.',
    'critical_warning_title': '중요 경고',
    'nuke_confirm_body': '보관함을 초기화하시겠습니까?\n\n⚠️ 계속하기 전에 모든 암호화폐 자금을 인출하고 파일을 저장하세요.\n\n이 작업은 되돌릴 수 없습니다. 애플리케이션이 초기 상태로 재설정됩니다.',
    'nuke_everything_button': '모두 파기',
    'got_it_button': '확인',
    'edit_name_title': '이름 수정',
    'save_button': '저장',
    'qr_code_button': 'QR 코드',
    'copy_id_button': 'ID 복사',
    'secure_crypto_vault_short': 'Secure\nCrypto Vault',
    'secure_vault_files_short': 'Secure\nVault Files',
    'privacy_id_label': '개인정보 ID',
    'profile_bio_paragraph': '군사급 제로 지식 암호화로 설계되었습니다.\n모든 통신은 엄격하게 P2P(피어 투 피어) 방식으로 작동합니다.\n메시지는 안전한 추적 방지 메모리 삭제 기술을 사용하여 24시간 후 자동으로 파기됩니다.\n흔적 없음, 로그 없음, 완전한 개인정보 보호.',
    'close_button': '닫기',
    'crypto_code_too_weak': '코드가 너무 약합니다: 최소 10자를 사용하고 반복되거나 순차적인 패턴을 피하세요.',
    'invalid_recovery_phrase': '복구 문구가 잘못되었습니다 - 단어를 확인하고 다시 시도하세요.',
    'crypto_vault_not_initialized': '이 기기에서 Crypto Vault가 초기화되지 않았습니다.',
    'invalid_crypto_vault_code': 'Crypto Vault 코드가 잘못되었습니다.',
    'crypto_vault_corrupted': 'Crypto Vault 데이터가 손상되었습니다(코드는 맞지만 보관함 파일 자체가 손상됨).',
    'create_crypto_vault_code_title': 'CRYPTO VAULT 코드 생성',
    'enter_crypto_vault_code_title': 'CRYPTO VAULT 코드 입력',
    'crypto_code_desc_create': '이 코드는 앱 및 Vault Files 코드와 별개입니다. 오직 사용자만 제어하는 완전히 새로운 비수탁형 지갑을 보호합니다.',
    'crypto_code_desc_enter': '지갑에 접근하려면 Crypto Vault 코드를 입력하세요.',
    'create_new_wallet_instead': '← 대신 새 지갑 만들기',
    'already_have_recovery_phrase': '이미 복구 문구가 있습니다 (휴대폰 분실 / 재설치)',
    'recovery_phrase_label': '12단어 복구 문구',
    'recovery_phrase_hint': '단어1 단어2 단어3 ...',
    'set_crypto_vault_code_label': 'Crypto Vault 코드 설정 (이 기기용)',
    'crypto_vault_code_label': 'Crypto Vault 코드',
    'restore_wallet_button': '지갑 복원',
    'create_wallet_button': '지갑 생성',
    'unlock_button': '잠금 해제',
    'recovery_phrase_title': '복구 문구',
    'recovery_phrase_warning': '⚠️ 이 12개 단어를 순서대로 종이에 적어 안전한 오프라인 장소에 보관하세요. 이 단어를 아는 사람은 누구나 자금을 훔칠 수 있습니다. Padlock은 이 문구를 어디에도 저장하지 않으며 대신 복구할 수 없습니다.',
    'recovery_phrase_confirm_checkbox': '이 단어들을 적어서 안전하게 오프라인으로 보관했습니다.',
    'continue_button': '계속',
    'loading_text': '로딩 중...',
    'could_not_load_balance': '잔액을 불러올 수 없습니다',
    'receive_dialog_title': '받기',
    'receive_address_warning': '이 코드를 스캔하거나 공유하면 지갑 주소만 노출됩니다 - 복구 문구는 절대 노출되지 않습니다.',
    'address_copied_toast': '주소가 복사되었습니다.',
    'copy_button': '복사',
    'testnet_warning': '⚠️ 테스트넷 (Polygon Amoy) - 실제 자금이 아닙니다.',
    'balances_label': '잔액',
    'receive_button': '받기',
    'send_button': '보내기',
    'camera_permission_denied': '카메라 권한이 거부되었습니다. 휴대폰 설정 > 앱 > Padlock > 권한에서 활성화하세요.',
    'scan_wallet_address_title': '지갑 주소 스캔',
    'invalid_wallet_address': '지갑 주소가 잘못되었습니다.',
    'enter_valid_amount': '유효한 금액을 입력하세요.',
    'price_not_loaded': '가격이 아직 로드되지 않았습니다 - 잠시 후 다시 시도하세요.',
    'transaction_sent_title': '거래 전송됨',
    'done_button': '완료',
    'send_failed_prefix': '전송 실패',
    'send_title': '보내기',
    'recipient_address_label': '수신자 지갑 주소',
    'coin_label': '코인',
    'amount_in_label': '단위:',
    'amount_usd_label': '금액 (USD)',
    'amount_label_prefix': '금액',
    'loading_price': '가격 로딩 중...',
    'price_label_prefix': '가격',
    'confirm_send_button': '확인 및 전송',
    'vault_files_not_initialized': '이 기기에서 Vault Files가 초기화되지 않았습니다.',
    'invalid_vault_files_code': 'Vault Files 코드가 올바르지 않습니다.',
    'vault_files_corrupted': 'Vault Files 데이터가 손상되었습니다(코드는 올바르지만 보관함 파일 자체가 손상됨).',
    'create_vault_files_code_title': 'VAULT FILES 코드 생성',
    'enter_vault_files_code_title': 'VAULT FILES 코드 입력',
    'vault_files_code_desc_create': '이 코드는 앱 잠금 해제 코드와 별개입니다. 앱 코드를 아는 사람도 이 코드 없이는 사진과 문서를 열 수 없습니다.',
    'vault_files_code_desc_enter': '암호화된 사진과 문서를 보려면 Vault Files 코드를 입력하세요.',
    'set_vault_files_code_label': 'Vault Files 코드 설정',
    'vault_files_code_label': 'Vault Files 코드',
    'create_vault_button': '보관함 생성',
    'imported_skipped_toast': '{imported}개 가져옴, {skipped}개 건너뜀(각 최대 {mb}MB).',
    'no_contacts_yet': '아직 연락처가 없습니다.',
    'send_to_title': '보낼 대상...',
    'sent_toast': '전송됨.',
    'failed_to_send_prefix': '전송 실패',
    'received_from_prefix': '보낸 사람',
    'sent_to_prefix': '받는 사람',
    'stored_locally_not_sent': '로컬에 저장됨 — 아직 아무에게도 전송되지 않음',
    'document_label': '문서',
    'document_stored_encrypted_desc': '이 문서는 Vault Files에 암호화되어 저장되어 있습니다({kb} KB). 내보내기를 사용해 휴대폰에 다시 저장하거나 공유하세요.',
    'export_button': '내보내기',
    'personal_files_empty': '아직 개인 파일이 없습니다.\n+ 버튼을 사용해 사진을 찍거나 문서를 가져오세요.',
    'received_files_empty': '아직 받은 것이 없습니다.',
    'sent_files_empty': '아직 보낸 것이 없습니다.',
    'tab_personal': '개인',
    'tab_received': '받은 항목',
    'tab_sent': '보낸 항목',
    'copy_message': '메시지 복사',
    'destroy_message': '메시지 파기',
    'node_destruction_title': '노드 파기',
    'destroy_message_confirm_body': '이 메시지를 두 기기 모두에서 영구적으로 파기하시겠습니까?',
    'destroy_button': '파기',
    'failed_to_send_photo_prefix': '사진 전송 실패',
    'encrypted_photo_sent_message': '🖼️ 암호화된 사진 전송됨 — Secure Vault Files에서 확인하세요',
    'photo_chat_preview': '🖼️ 사진',
    'just_now': '방금 전',
    'failed_to_send_voice_prefix': '음성 메시지 전송 실패',
    'voice_message_chat_preview': '🎤 음성 메시지',
    'voice_message_label': '음성 메시지',
    'no_secure_channel_error': '전송할 수 없습니다: 이 연락처와 아직 보안 채널이 없습니다({error}). 삭제 후 다시 추가해 보세요.',
    'block_id_title': 'ID 차단',
    'block_id_confirm_body': '이 ID를 영구적으로 차단하시겠습니까?',
    'block_button': '차단',
    'keys_not_available': '이 연락처의 키를 사용할 수 없습니다.',
    'safety_number_title': '안전 번호',
    'safety_number_desc': '이 연락처와 안전한 통화를 하고 이 번호를 소리 내어 읽어보세요. 두 기기에서 번호가 일치하면 아무도 대화를 가로채지 않는 것입니다.',
    'verify_safety_number': '안전 번호 확인',
    'encrypted_p2p_channel': '암호화된 P2P 채널',
    'destruct_1m': '1분',
    'destruct_5m': '5분',
    'destruct_1h': '1시간',
    'destruct_24h': '24시간',
    'message_not_decrypted': '[메시지가 복호화되지 않았습니다]',
    'call_status_connecting': '연결 중...',
    'call_status_exchanging_keys': '암호화 키 교환 중...',
    'call_status_ringing': '전화가 울리는 중...',
    'call_status_connecting_encrypted': '암호화된 통화 연결 중...',
    'call_status_incoming_encrypted': '수신 중인 암호화된 통화...',
    'call_status_connected_prefix': '연결됨',
    'call_status_connected_encrypted': '연결되고 암호화됨',
    'call_status_reconnecting': '재연결 중...',
    'call_contact_unavailable': '연락처를 사용할 수 없거나 오프라인입니다.',
    'missed_secure_call': '부재중 보안 통화',
    'missed_call_notification_title': '부재중 전화',
    'setup_code_too_weak': '암호 해독 키가 너무 약합니다: 최소 10자를 사용하고 반복되거나 연속된 패턴을 피하세요.',
    'vault_init_failed_prefix': '보관함 초기화 실패',
    'create_vault_title': '암호화된 보관함 만들기',
    'create_vault_subtitle': '마스터 키를 설정하여\nP2P 암호화 신원을 생성하세요',
    'set_decryption_key_label': '암호 해독 키 설정',
    'strength_too_weak': '너무 약함',
    'strength_weak': '약함',
    'strength_medium': '보통',
    'strength_strong': '강함',
    'strength_very_strong': '매우 강함',
    'initialize_vault_button': '보관함 초기화',
    'footer_privacy_text': '군사급 제로 지식 암호화로 설계되었습니다.\n모든 통신은 엄격하게 P2P(피어 투 피어) 방식으로 작동합니다.\n메시지는 안전한 흔적 방지 메모리 정화를 통해\n24시간 후 자동으로 파기됩니다.\n흔적 없음, 로그 없음, 완전한 프라이버시.',
    'vault_not_initialized_device': '이 기기에서 보관함이 초기화되지 않았습니다.',
    'invalid_decryption_key': '잘못된 암호 해독 키입니다.',
    'vault_data_corrupted': '보관함 데이터가 손상되었습니다(키는 올바르지만 보관함 파일 자체가 손상됨).',
    'decrypt_padlock_title': 'PADLOCK 잠금 해제',
    'login_subtitle': '군사급 제로 지식 암호화로 설계되었습니다',
    'enter_decryption_key_label': '암호 해독 키 입력',
    'access_vault_button': '보관함 접속',
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
    'language': 'اللغة',
    'search_contact_hint': 'بحث عن جهة اتصال...',
    'encrypted_p2p_contact': 'جهة اتصال مشفّرة نظير إلى نظير',
    'encrypted_p2p_message_preview': '[رسالة مشفّرة نظير إلى نظير]',
    'delete_chat_confirm_title': 'حذف المحادثة',
    'delete_chat_confirm_body': 'هل تريد حذف هذه المحادثة نهائيًا؟',
    'cancel_button': 'إلغاء',
    'delete_button': 'حذف',
    'settings_header': 'الإعدادات',
    'section_core_security': 'بروتوكولات الأمان الأساسية',
    'info_encryption_title': 'تشفير بمستوى عسكري',
    'info_encryption_desc': 'معيار AES-256-GCM و Curve25519.',
    'info_p2p_title': 'اتصال نظير إلى نظير حقيقي',
    'info_p2p_desc': 'صوت وبيانات مباشرة. بدون توجيه عبر الخادم.',
    'info_autodestruct_title': 'تدمير ذاتي جنائي',
    'info_autodestruct_desc': 'يتم إتلاف جميع الرسائل خلال 24 ساعة كحد أقصى.',
    'info_screenshot_title': 'حماية من لقطات الشاشة',
    'info_screenshot_desc': 'يتم حظر التقاط الشاشة على مستوى التطبيق بالكامل لمنع تسرب البيانات غير المصرح به.',
    'info_timeout_title': 'إغلاق تلقائي آمن',
    'info_timeout_desc': 'يُغلق التطبيق تلقائيًا بعد 15 دقيقة من الاستخدام لحمايتك. يلزم تسجيل الدخول مجددًا للمتابعة. تتجاوز المكالمات النشطة هذه القاعدة للحفاظ على الاتصال.',
    'section_premium': 'Padlock Premium',
    'secure_crypto_vault_title': 'Secure Crypto Vault',
    'crypto_vault_desc': 'تخزين بأقصى درجات الأمان لأصولك الرقمية.',
    'section_help_center': 'مركز المساعدة / كيفية الاستخدام',
    'help_vault_files_q': 'كيف تستخدم Secure Vault Files؟',
    'help_vault_files_a': 'للوصول إلى هذا القسم، يجب إنشاء مفتاح مشفّر مخصص. في كل مرة تفتح فيها الخزنة، سيُطلب منك هذا المفتاح لتسجيل الدخول، تمامًا مثل تسجيل دخول أمان التطبيق.\n\n• يتم حفظ جميع الصور الملتقطة مباشرة داخل Padlock هنا تلقائيًا.\n• يتم توجيه المستندات والصور المرسلة من جهات الاتصال إلى معرّفك مباشرة إلى هذه الخزنة بدلاً من الدردشات العادية. ستتلقى تنبيهًا بأن وسائط أُرسلت، ويجب عليك الوصول إليها داخل الخزنة لعرضها.\n• تظل الملفات مشفّرة وآمنة بنسبة 100% حتى يتم حذفها أو تصديرها أو إعادة إرسالها يدويًا.',
    'help_add_contact_q': 'كيف تضيف جهة اتصال؟',
    'help_add_contact_a': 'اذهب إلى علامة التبويب "جهات الاتصال"، اضغط على الزر الأزرق (+)، والصق معرّف الخصوصية أو استخدم ماسح رمز QR الأخضر.',
    'help_share_id_q': 'كيف أشارك معرّفي؟',
    'help_share_id_a': 'اذهب إلى علامة التبويب "الملف الشخصي". اضغط على "Copy ID" للصقه بأمان في أي مكان، أو "QR Code" ليقوم شخص ما بمسح شاشتك.',
    'help_rename_contact_q': 'كيف تعيد تسمية جهة اتصال؟',
    'help_rename_contact_a': 'في علامة التبويب "جهات الاتصال"، اضغط على أيقونة التعديل (القلم) بجانب أي جهة اتصال لتغيير اسمها المعروض.',
    'help_delete_contact_q': 'كيف تحذف جهة اتصال؟',
    'help_delete_contact_a': 'في علامة التبويب "جهات الاتصال"، اضغط مطولاً على أي جهة اتصال. سيؤدي هذا إلى حذفها نهائيًا وإتلاف مفاتيح التشفير المشتركة.',
    'help_wipe_chat_q': 'كيف تمسح محادثة؟',
    'help_wipe_chat_a': 'داخل أي محادثة نشطة، اضغط على القائمة (ثلاث نقاط) في الزاوية العلوية اليمنى واختر "حذف المحادثة" لإتلاف جميع الرسائل على كلا الجهازين.',
    'section_app_preferences': 'تفضيلات التطبيق',
    'app_language_title': 'لغة التطبيق',
    'current_lang_prefix': 'الحالية',
    'silent_mode_desc': 'كتم جميع الإشعارات ونغمات المكالمات.',
    'section_panic_room': 'غرفة الطوارئ',
    'nuke_vault_title': 'تدمير الخزنة: مسح وتدمير كل شيء',
    'nuke_vault_desc': 'سيؤدي هذا الإجراء إلى إتلاف معرّف الخصوصية وأموال العملات المشفرة وجميع المحادثات نهائيًا. يمسح كل شيء ويعيدك إلى شاشة التفعيل.',
    'critical_warning_title': 'تحذير بالغ الأهمية',
    'nuke_confirm_body': 'هل أنت متأكد من رغبتك في تدمير الخزنة؟\n\n⚠️ اسحب جميع أموال العملات المشفرة واحفظ ملفاتك قبل المتابعة.\n\nهذا الإجراء لا رجعة فيه. سيتم إعادة ضبط التطبيق إلى حالة المصنع.',
    'nuke_everything_button': 'تدمير كل شيء',
    'got_it_button': 'فهمت',
    'edit_name_title': 'تعديل الاسم',
    'save_button': 'حفظ',
    'qr_code_button': 'رمز QR',
    'copy_id_button': 'نسخ المعرّف',
    'secure_crypto_vault_short': 'Secure\nCrypto Vault',
    'secure_vault_files_short': 'Secure\nVault Files',
    'privacy_id_label': 'معرّف الخصوصية',
    'profile_bio_paragraph': 'مصمم بتشفير Zero-Knowledge بمستوى عسكري.\nتعمل جميع الاتصالات بشكل صارم نظير إلى نظير (P2P).\nتُدمَّر الرسائل تلقائيًا بعد 24 ساعة\nباستخدام تعقيم ذاكرة آمن مضاد للتتبع.\nبدون أثر، بدون سجلات، خصوصية تامة.',
    'close_button': 'إغلاق',
    'crypto_code_too_weak': 'الرمز ضعيف جدًا: استخدم 10 أحرف على الأقل وتجنب الأنماط المتكررة أو المتسلسلة.',
    'invalid_recovery_phrase': 'عبارة الاسترداد غير صالحة - تحقق من الكلمات وحاول مرة أخرى.',
    'crypto_vault_not_initialized': 'لم يتم تهيئة Crypto Vault على هذا الجهاز.',
    'invalid_crypto_vault_code': 'رمز Crypto Vault غير صالح.',
    'crypto_vault_corrupted': 'بيانات Crypto Vault تالفة (الرمز كان صحيحًا، لكن ملف الخزنة نفسه تالف).',
    'create_crypto_vault_code_title': 'إنشاء رمز CRYPTO VAULT',
    'enter_crypto_vault_code_title': 'أدخل رمز CRYPTO VAULT',
    'crypto_code_desc_create': 'هذا الرمز منفصل عن رمز التطبيق ورموز Vault Files. إنه يحمي محفظة جديدة تمامًا غير وصائية تتحكم فيها أنت فقط.',
    'crypto_code_desc_enter': 'أدخل رمز Crypto Vault للوصول إلى محفظتك.',
    'create_new_wallet_instead': '← إنشاء محفظة جديدة بدلاً من ذلك',
    'already_have_recovery_phrase': 'لدي بالفعل عبارة استرداد (فقدت الهاتف / أعدت التثبيت)',
    'recovery_phrase_label': 'عبارة الاسترداد المكونة من 12 كلمة',
    'recovery_phrase_hint': 'كلمة1 كلمة2 كلمة3 ...',
    'set_crypto_vault_code_label': 'تعيين رمز Crypto Vault (لهذا الجهاز)',
    'crypto_vault_code_label': 'رمز Crypto Vault',
    'restore_wallet_button': 'استعادة المحفظة',
    'create_wallet_button': 'إنشاء المحفظة',
    'unlock_button': 'إلغاء القفل',
    'recovery_phrase_title': 'عبارة الاسترداد الخاصة بك',
    'recovery_phrase_warning': '⚠️ اكتب هذه الكلمات الـ 12 على ورقة، بالترتيب، واحتفظ بها في مكان آمن وغير متصل بالإنترنت. يمكن لأي شخص يملك هذه الكلمات سرقة أموالك. لا تخزّن Padlock هذه العبارة في أي مكان ولا يمكنها استعادتها لك.',
    'recovery_phrase_confirm_checkbox': 'لقد كتبت هذه الكلمات وحفظتها بأمان دون اتصال بالإنترنت.',
    'continue_button': 'متابعة',
    'loading_text': 'جارٍ التحميل...',
    'could_not_load_balance': 'تعذّر تحميل الرصيد',
    'receive_dialog_title': 'استلام',
    'receive_address_warning': 'مسح أو مشاركة هذا الرمز يكشف فقط عن عنوان محفظتك - وليس عبارة الاسترداد أبدًا.',
    'address_copied_toast': 'تم نسخ العنوان.',
    'copy_button': 'نسخ',
    'testnet_warning': '⚠️ شبكة اختبار (Polygon Amoy) - هذه ليست أموالًا حقيقية.',
    'balances_label': 'الأرصدة',
    'receive_button': 'استلام',
    'send_button': 'إرسال',
    'camera_permission_denied': 'تم رفض إذن الكاميرا. فعّله في إعدادات الهاتف > التطبيقات > Padlock > الأذونات.',
    'scan_wallet_address_title': 'مسح عنوان المحفظة',
    'invalid_wallet_address': 'عنوان محفظة غير صالح.',
    'enter_valid_amount': 'أدخل مبلغًا صالحًا.',
    'price_not_loaded': 'لم يتم تحميل السعر بعد - حاول مرة أخرى بعد قليل.',
    'transaction_sent_title': 'تم إرسال المعاملة',
    'done_button': 'تم',
    'send_failed_prefix': 'فشل الإرسال',
    'send_title': 'إرسال',
    'recipient_address_label': 'عنوان محفظة المستلم',
    'coin_label': 'العملة',
    'amount_in_label': 'المبلغ بـ:',
    'amount_usd_label': 'المبلغ (USD)',
    'amount_label_prefix': 'المبلغ',
    'loading_price': 'جارٍ تحميل السعر...',
    'price_label_prefix': 'السعر',
    'confirm_send_button': 'تأكيد وإرسال',
    'vault_files_not_initialized': 'لم يتم تهيئة Vault Files على هذا الجهاز.',
    'invalid_vault_files_code': 'رمز Vault Files غير صالح.',
    'vault_files_corrupted': 'بيانات Vault Files تالفة (الرمز كان صحيحًا، لكن ملف الخزنة نفسه تالف).',
    'create_vault_files_code_title': 'إنشاء رمز VAULT FILES',
    'enter_vault_files_code_title': 'أدخل رمز VAULT FILES',
    'vault_files_code_desc_create': 'هذا الرمز منفصل عن رمز فتح التطبيق. لن يتمكن أي شخص يعرف رمز التطبيق من فتح صورك ومستنداتك بدون هذا الرمز أيضًا.',
    'vault_files_code_desc_enter': 'أدخل رمز Vault Files لعرض صورك ومستنداتك المشفرة.',
    'set_vault_files_code_label': 'تعيين رمز Vault Files',
    'vault_files_code_label': 'رمز Vault Files',
    'create_vault_button': 'إنشاء الخزنة',
    'imported_skipped_toast': 'تم استيراد {imported}، تم تخطي {skipped} (بحد أقصى {mb} ميغابايت لكل ملف).',
    'no_contacts_yet': 'لا توجد جهات اتصال بعد.',
    'send_to_title': 'إرسال إلى...',
    'sent_toast': 'تم الإرسال.',
    'failed_to_send_prefix': 'فشل الإرسال',
    'received_from_prefix': 'مستلم من',
    'sent_to_prefix': 'مرسل إلى',
    'stored_locally_not_sent': 'محفوظ محليًا — لم يُرسل لأحد بعد',
    'document_label': 'مستند',
    'document_stored_encrypted_desc': 'هذا المستند محفوظ مشفرًا في Vault Files ({kb} كيلوبايت). استخدم تصدير لحفظه مرة أخرى على هاتفك أو مشاركته.',
    'export_button': 'تصدير',
    'personal_files_empty': 'لا توجد ملفات شخصية بعد.\nاستخدم زر + لالتقاط صورة أو استيراد مستند.',
    'received_files_empty': 'لم يتم استلام شيء بعد.',
    'sent_files_empty': 'لم يتم إرسال شيء بعد.',
    'tab_personal': 'شخصي',
    'tab_received': 'المستلمة',
    'tab_sent': 'المرسلة',
    'copy_message': 'نسخ الرسالة',
    'destroy_message': 'تدمير الرسالة',
    'node_destruction_title': 'تدمير العقدة',
    'destroy_message_confirm_body': 'هل تريد تدمير هذه الرسالة نهائيًا على كلا الجهازين؟',
    'destroy_button': 'تدمير',
    'failed_to_send_photo_prefix': 'فشل إرسال الصورة',
    'encrypted_photo_sent_message': '🖼️ تم إرسال صورة مشفرة — شاهدها في Secure Vault Files',
    'photo_chat_preview': '🖼️ صورة',
    'just_now': 'الآن',
    'failed_to_send_voice_prefix': 'فشل إرسال الرسالة الصوتية',
    'voice_message_chat_preview': '🎤 رسالة صوتية',
    'voice_message_label': 'رسالة صوتية',
    'no_secure_channel_error': 'تعذر الإرسال: لا توجد قناة آمنة بعد مع جهة الاتصال هذه ({error}). حاول حذفها وإضافتها مرة أخرى.',
    'block_id_title': 'حظر المعرّف',
    'block_id_confirm_body': 'هل تريد حظر هذا المعرّف نهائيًا؟',
    'block_button': 'حظر',
    'keys_not_available': 'المفاتيح غير متوفرة لجهة الاتصال هذه.',
    'safety_number_title': 'رقم الأمان',
    'safety_number_desc': 'قم بإجراء مكالمة آمنة مع جهة الاتصال هذه واقرأ هذا الرقم بصوت عالٍ. إذا تطابق على كلا الجهازين، فلا أحد يعترض محادثتك.',
    'verify_safety_number': 'التحقق من رقم الأمان',
    'encrypted_p2p_channel': 'قناة P2P مشفرة',
    'destruct_1m': 'دقيقة واحدة',
    'destruct_5m': '5 دقائق',
    'destruct_1h': 'ساعة واحدة',
    'destruct_24h': '24 ساعة',
    'message_not_decrypted': '[لم يتم فك تشفير الرسالة]',
    'call_status_connecting': 'جارٍ الاتصال...',
    'call_status_exchanging_keys': 'جارٍ تبادل مفاتيح التشفير...',
    'call_status_ringing': 'جارٍ الرنين...',
    'call_status_connecting_encrypted': 'جارٍ إجراء مكالمة مشفرة...',
    'call_status_incoming_encrypted': 'مكالمة واردة مشفرة...',
    'call_status_connected_prefix': 'متصل',
    'call_status_connected_encrypted': 'متصل ومشفر',
    'call_status_reconnecting': 'جارٍ إعادة الاتصال...',
    'call_contact_unavailable': 'جهة الاتصال غير متاحة أو غير متصلة.',
    'missed_secure_call': 'مكالمة آمنة فائتة',
    'missed_call_notification_title': 'مكالمة فائتة',
    'setup_code_too_weak': 'مفتاح فك التشفير ضعيف جدًا: استخدم 10 أحرف على الأقل وتجنب الأنماط المتكررة أو المتسلسلة.',
    'vault_init_failed_prefix': 'فشل تهيئة الخزنة',
    'create_vault_title': 'أنشئ خزنتك المشفرة',
    'create_vault_subtitle': 'عيّن مفتاحك الرئيسي لإنشاء\nهويتك التشفيرية من نظير إلى نظير',
    'set_decryption_key_label': 'تعيين مفتاح فك التشفير',
    'strength_too_weak': 'ضعيف جدًا',
    'strength_weak': 'ضعيف',
    'strength_medium': 'متوسط',
    'strength_strong': 'قوي',
    'strength_very_strong': 'قوي جدًا',
    'initialize_vault_button': 'تهيئة الخزنة',
    'footer_privacy_text': 'مصمم بتشفير Zero-Knowledge بمستوى عسكري.\nتعمل جميع الاتصالات بشكل صارم من نظير إلى نظير (P2P).\nتُدمَّر الرسائل تلقائيًا بعد 24 ساعة\nباستخدام تنظيف ذاكرة آمن مضاد للتتبع.\nصفر أثر، صفر سجلات، خصوصية تامة.',
    'vault_not_initialized_device': 'الخزنة غير مهيأة على هذا الجهاز.',
    'invalid_decryption_key': 'مفتاح فك التشفير غير صالح.',
    'vault_data_corrupted': 'بيانات الخزنة تالفة (كان المفتاح صحيحًا، لكن ملف الخزنة نفسه تالف).',
    'decrypt_padlock_title': 'فك تشفير Padlock الخاص بك',
    'login_subtitle': 'مصمم بتشفير Zero-Knowledge بمستوى عسكري',
    'enter_decryption_key_label': 'أدخل مفتاح فك التشفير',
    'access_vault_button': 'الدخول إلى الخزنة',
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
    'language': 'Dil',
    'search_contact_hint': 'Kişi ara...',
    'encrypted_p2p_contact': 'Şifreli P2P Kişi',
    'encrypted_p2p_message_preview': '[Şifreli P2P Mesajı]',
    'delete_chat_confirm_title': 'Sohbeti Sil',
    'delete_chat_confirm_body': 'Bu sohbeti kalıcı olarak silmek istiyor musunuz?',
    'cancel_button': 'İptal',
    'delete_button': 'Sil',
    'settings_header': 'AYARLAR',
    'section_core_security': 'Temel Güvenlik Protokolleri',
    'info_encryption_title': 'Askeri Düzeyde Şifreleme',
    'info_encryption_desc': 'AES-256-GCM ve Curve25519 standardı.',
    'info_p2p_title': 'Gerçek Eşler Arası (P2P)',
    'info_p2p_desc': 'Doğrudan ses ve veri. Sıfır sunucu yönlendirmesi.',
    'info_autodestruct_title': 'Adli Otomatik İmha',
    'info_autodestruct_desc': 'Tüm mesajlar en fazla 24 saat içinde yok edilir.',
    'info_screenshot_title': 'Ekran Görüntüsü Koruması',
    'info_screenshot_desc': 'Yetkisiz veri sızıntılarını önlemek için ekran yakalama uygulama genelinde engellenir.',
    'info_timeout_title': 'Güvenli Zaman Aşımı',
    'info_timeout_desc': 'Güvenliğiniz için uygulama 15 dakika kullanımdan sonra otomatik olarak kapanır. Devam etmek için yeniden giriş gereklidir. Aktif aramalar bağlantıyı korumak için bu kuralı yok sayar.',
    'section_premium': 'Padlock Premium',
    'secure_crypto_vault_title': 'Secure Crypto Vault',
    'crypto_vault_desc': 'Dijital varlıklarınız için maksimum güvenlikli depolama.',
    'section_help_center': 'Yardım Merkezi / Nasıl Kullanılır',
    'help_vault_files_q': 'Secure Vault Files nasıl kullanılır?',
    'help_vault_files_a': 'Bu bölüme erişmek için özel bir şifreli anahtar oluşturmanız gerekir. Kasayı her açtığınızda, uygulama güvenlik girişi gibi bu anahtarı isteyecektir.\n\n• Doğrudan Padlock içinde çekilen tüm fotoğraflar otomatik olarak buraya kaydedilir.\n• Kişilerin ID\'nize gönderdiği belgeler ve fotoğraflar normal sohbetler yerine doğrudan bu kasaya yönlendirilir. Medya gönderildiğine dair bir bildirim alacaksınız ve görüntülemek için kasaya erişmeniz gerekir.\n• Dosyalar manuel olarak silinene, dışa aktarılana veya yeniden gönderilene kadar %100 şifreli ve güvenli kalır.',
    'help_add_contact_q': 'Kişi nasıl eklenir?',
    'help_add_contact_a': '"Kişiler" sekmesine gidin, mavi (+) düğmesine dokunun ve bir Gizlilik Kimliği yapıştırın veya yeşil QR tarayıcıyı kullanın.',
    'help_share_id_q': 'Kimliğimi nasıl paylaşırım?',
    'help_share_id_a': '"Profil" sekmesine gidin. Herhangi bir yere güvenle yapıştırmak için "Copy ID"ye veya birinin ekranınızı taraması için "QR Code"a dokunun.',
    'help_rename_contact_q': 'Bir kişi nasıl yeniden adlandırılır?',
    'help_rename_contact_a': '"Kişiler" sekmesinde, görünen adını değiştirmek için herhangi bir kişinin yanındaki Düzenle (kalem) simgesine dokunun.',
    'help_delete_contact_q': 'Bir kişi nasıl silinir?',
    'help_delete_contact_a': '"Kişiler" sekmesinde herhangi bir kişiye uzun basın. Bu, kişiyi kalıcı olarak siler ve paylaşılan şifreleme anahtarlarını yok eder.',
    'help_wipe_chat_q': 'Bir konuşma nasıl silinir?',
    'help_wipe_chat_a': 'Herhangi bir aktif sohbette, sağ üst köşedeki menüye (üç nokta) dokunun ve her iki cihazdaki tüm mesajları yok etmek için "Sohbeti Sil"i seçin.',
    'section_app_preferences': 'Uygulama Tercihleri',
    'app_language_title': 'Uygulama Dili',
    'current_lang_prefix': 'Mevcut',
    'silent_mode_desc': 'Tüm bildirimleri ve arama zil seslerini susturur.',
    'section_panic_room': 'Panik Odası',
    'nuke_vault_title': 'KASAYI İMHA ET: HER ŞEYİ TEMİZLE VE YOK ET',
    'nuke_vault_desc': 'Bu işlem Gizlilik Kimliğinizi, kripto varlıklarınızı ve tüm sohbetlerinizi kalıcı olarak yok edecektir. Her şeyi temizler ve sizi etkinleştirme ekranına geri götürür.',
    'critical_warning_title': 'KRİTİK UYARI',
    'nuke_confirm_body': 'Kasayı İMHA ETMEK istediğinizden emin misiniz?\n\n⚠️ DEVAM ETMEDEN ÖNCE TÜM KRİPTO VARLIKLARINI ÇEKİN VE DOSYALARINIZI KAYDEDİN.\n\nBu işlem geri alınamaz. Uygulama fabrika durumuna sıfırlanacaktır.',
    'nuke_everything_button': 'HER ŞEYİ YOK ET',
    'got_it_button': 'Anladım',
    'edit_name_title': 'Adı Düzenle',
    'save_button': 'Kaydet',
    'qr_code_button': 'QR Kodu',
    'copy_id_button': 'Kimliği Kopyala',
    'secure_crypto_vault_short': 'Secure\nCrypto Vault',
    'secure_vault_files_short': 'Secure\nVault Files',
    'privacy_id_label': 'Gizlilik Kimliği',
    'profile_bio_paragraph': 'Askeri düzeyde Sıfır Bilgi şifrelemesiyle tasarlandı.\nTüm iletişimler kesinlikle Eşler Arası (P2P) çalışır.\nMesajlar, güvenli iz karşıtı bellek temizleme kullanılarak 24 saat sonra otomatik olarak kendini imha eder.\nSıfır iz, sıfır günlük, tam gizlilik.',
    'close_button': 'Kapat',
    'crypto_code_too_weak': 'Kod çok zayıf: en az 10 karakter kullanın ve tekrarlanan veya sıralı desenlerden kaçının.',
    'invalid_recovery_phrase': 'Geçersiz kurtarma ifadesi - kelimeleri kontrol edin ve tekrar deneyin.',
    'crypto_vault_not_initialized': 'Bu cihazda Crypto Vault başlatılmadı.',
    'invalid_crypto_vault_code': 'Geçersiz Crypto Vault kodu.',
    'crypto_vault_corrupted': 'Crypto Vault verileri bozuk (kod doğruydu, ancak kasa dosyasının kendisi hasarlı).',
    'create_crypto_vault_code_title': 'CRYPTO VAULT KODU OLUŞTUR',
    'enter_crypto_vault_code_title': 'CRYPTO VAULT KODUNU GİRİN',
    'crypto_code_desc_create': 'Bu kod, uygulama ve Vault Files kodlarından ayrıdır. Yalnızca sizin kontrol ettiğiniz yepyeni, saklayıcısız bir cüzdanı korur.',
    'crypto_code_desc_enter': 'Cüzdanınıza erişmek için Crypto Vault kodunuzu girin.',
    'create_new_wallet_instead': '← Bunun yerine yeni bir cüzdan oluştur',
    'already_have_recovery_phrase': 'Zaten bir kurtarma ifadem var (telefon kayboldu / yeniden kuruldu)',
    'recovery_phrase_label': '12 kelimelik kurtarma ifadeniz',
    'recovery_phrase_hint': 'kelime1 kelime2 kelime3 ...',
    'set_crypto_vault_code_label': 'Crypto Vault Kodu Belirle (BU cihaz için)',
    'crypto_vault_code_label': 'Crypto Vault Kodu',
    'restore_wallet_button': 'CÜZDANI GERİ YÜKLE',
    'create_wallet_button': 'CÜZDAN OLUŞTUR',
    'unlock_button': 'KİLİDİ AÇ',
    'recovery_phrase_title': 'Kurtarma İfadeniz',
    'recovery_phrase_warning': '⚠️ Bu 12 kelimeyi sırayla kağıda yazın ve güvenli, çevrimdışı bir yerde saklayın. Bu kelimelere sahip olan herkes fonlarınızı çalabilir. Padlock bu ifadeyi hiçbir yerde saklamaz ve sizin için kurtaramaz.',
    'recovery_phrase_confirm_checkbox': 'Bu kelimeleri yazdım ve çevrimdışı olarak güvenli bir şekilde sakladım.',
    'continue_button': 'DEVAM ET',
    'loading_text': 'Yükleniyor...',
    'could_not_load_balance': 'Bakiye yüklenemedi',
    'receive_dialog_title': 'Al',
    'receive_address_warning': 'Bu kodu taramak veya paylaşmak yalnızca cüzdan ADRESİNİZİ verir - kurtarma ifadenizi asla vermez.',
    'address_copied_toast': 'Adres kopyalandı.',
    'copy_button': 'KOPYALA',
    'testnet_warning': '⚠️ TEST AĞI (Polygon Amoy) - bunlar GERÇEK paralar değildir.',
    'balances_label': 'Bakiyeler',
    'receive_button': 'AL',
    'send_button': 'GÖNDER',
    'camera_permission_denied': 'Kamera izni reddedildi. Telefon Ayarları > Uygulamalar > Padlock > İzinler bölümünden etkinleştirin.',
    'scan_wallet_address_title': 'Cüzdan Adresini Tara',
    'invalid_wallet_address': 'Geçersiz cüzdan adresi.',
    'enter_valid_amount': 'Geçerli bir miktar girin.',
    'price_not_loaded': 'Fiyat henüz yüklenmedi - birazdan tekrar deneyin.',
    'transaction_sent_title': 'İşlem Gönderildi',
    'done_button': 'BİTTİ',
    'send_failed_prefix': 'Gönderme başarısız',
    'send_title': 'Gönder',
    'recipient_address_label': 'Alıcı cüzdan adresi',
    'coin_label': 'Coin',
    'amount_in_label': 'Miktar birimi:',
    'amount_usd_label': 'Miktar (USD)',
    'amount_label_prefix': 'Miktar',
    'loading_price': 'Fiyat yükleniyor...',
    'price_label_prefix': 'Fiyat',
    'confirm_send_button': 'ONAYLA VE GÖNDER',
    'vault_files_not_initialized': 'Vault Files bu cihazda başlatılmadı.',
    'invalid_vault_files_code': 'Geçersiz Vault Files kodu.',
    'vault_files_corrupted': 'Vault Files verileri bozuk (kod doğruydu, ancak kasa dosyasının kendisi hasarlı).',
    'create_vault_files_code_title': 'VAULT FILES KODU OLUŞTUR',
    'enter_vault_files_code_title': 'VAULT FILES KODUNU GİRİN',
    'vault_files_code_desc_create': 'Bu kod, uygulama kilidini açma kodunuzdan ayrıdır. Uygulama kodunu bilen biri bu kod olmadan fotoğraflarınızı ve belgelerinizi açamayacaktır.',
    'vault_files_code_desc_enter': 'Şifrelenmiş fotoğraflarınızı ve belgelerinizi görüntülemek için Vault Files kodunuzu girin.',
    'set_vault_files_code_label': 'Vault Files Kodunu Belirle',
    'vault_files_code_label': 'Vault Files Kodu',
    'create_vault_button': 'KASA OLUŞTUR',
    'imported_skipped_toast': '{imported} içe aktarıldı, {skipped} atlandı (her biri en fazla {mb}MB).',
    'no_contacts_yet': 'Henüz kişi yok.',
    'send_to_title': 'Şuna gönder...',
    'sent_toast': 'Gönderildi.',
    'failed_to_send_prefix': 'Gönderme başarısız oldu',
    'received_from_prefix': 'Şuradan alındı',
    'sent_to_prefix': 'Şuna gönderildi',
    'stored_locally_not_sent': 'Yerel olarak saklandı — henüz kimseye gönderilmedi',
    'document_label': 'Belge',
    'document_stored_encrypted_desc': 'Bu belge, Vault Files\'ınızda şifrelenmiş olarak saklanıyor ({kb} KB). Telefonunuza geri kaydetmek veya paylaşmak için Dışa Aktar\'ı kullanın.',
    'export_button': 'Dışa Aktar',
    'personal_files_empty': 'Henüz kişisel dosya yok.\nFotoğraf çekmek veya belge içe aktarmak için + düğmesini kullanın.',
    'received_files_empty': 'Henüz bir şey alınmadı.',
    'sent_files_empty': 'Henüz bir şey gönderilmedi.',
    'tab_personal': 'Kişisel',
    'tab_received': 'Alınanlar',
    'tab_sent': 'Gönderilenler',
    'copy_message': 'Mesajı Kopyala',
    'destroy_message': 'Mesajı Yok Et',
    'node_destruction_title': 'Düğüm İmhası',
    'destroy_message_confirm_body': 'Bu mesajı her iki cihazda da kalıcı olarak yok etmek istiyor musunuz?',
    'destroy_button': 'Yok Et',
    'failed_to_send_photo_prefix': 'Fotoğraf gönderilemedi',
    'encrypted_photo_sent_message': '🖼️ Şifreli fotoğraf gönderildi — Secure Vault Files\'ta görüntüleyin',
    'photo_chat_preview': '🖼️ Fotoğraf',
    'just_now': 'Az önce',
    'failed_to_send_voice_prefix': 'Sesli mesaj gönderilemedi',
    'voice_message_chat_preview': '🎤 Sesli mesaj',
    'voice_message_label': 'Sesli mesaj',
    'no_secure_channel_error': 'Gönderilemedi: bu kişiyle henüz güvenli bir kanal yok ({error}). Kişiyi kaldırıp yeniden eklemeyi deneyin.',
    'block_id_title': 'Kimliği Engelle',
    'block_id_confirm_body': 'Bu kimliği kalıcı olarak engellemek istiyor musunuz?',
    'block_button': 'Engelle',
    'keys_not_available': 'Bu kişi için anahtarlar mevcut değil.',
    'safety_number_title': 'Güvenlik Numarası',
    'safety_number_desc': 'Bu kişiyle güvenli bir arama yapın ve bu numarayı yüksek sesle okuyun. Her iki cihazda da eşleşiyorsa, konuşmanızı kimse dinlemiyor demektir.',
    'verify_safety_number': 'Güvenlik Numarasını Doğrula',
    'encrypted_p2p_channel': 'Şifreli P2P Kanalı',
    'destruct_1m': '1 Dakika',
    'destruct_5m': '5 Dakika',
    'destruct_1h': '1 Saat',
    'destruct_24h': '24 Saat',
    'message_not_decrypted': '[Mesaj çözülemedi]',
    'call_status_connecting': 'Bağlanıyor...',
    'call_status_exchanging_keys': 'Şifreleme anahtarları değiştiriliyor...',
    'call_status_ringing': 'Çalıyor...',
    'call_status_connecting_encrypted': 'Şifreli arama bağlanıyor...',
    'call_status_incoming_encrypted': 'Gelen şifreli arama...',
    'call_status_connected_prefix': 'Bağlandı',
    'call_status_connected_encrypted': 'Bağlandı ve şifrelendi',
    'call_status_reconnecting': 'Yeniden bağlanıyor...',
    'call_contact_unavailable': 'Kişi kullanılamıyor veya çevrimdışı.',
    'missed_secure_call': 'Cevapsız Güvenli Arama',
    'missed_call_notification_title': 'Cevapsız Arama',
    'setup_code_too_weak': 'Şifre çözme anahtarı çok zayıf: en az 10 karakter kullanın ve tekrarlayan veya ardışık desenlerden kaçının.',
    'vault_init_failed_prefix': 'Kasa başlatma başarısız oldu',
    'create_vault_title': 'ŞİFRELİ KASANIZI OLUŞTURUN',
    'create_vault_subtitle': 'P2P kriptografik kimliğinizi oluşturmak için\nana anahtarınızı belirleyin',
    'set_decryption_key_label': 'Şifre Çözme Anahtarını Belirle',
    'strength_too_weak': 'Çok zayıf',
    'strength_weak': 'Zayıf',
    'strength_medium': 'Orta',
    'strength_strong': 'Güçlü',
    'strength_very_strong': 'Çok güçlü',
    'initialize_vault_button': 'KASAYI BAŞLAT',
    'footer_privacy_text': 'Askeri düzeyde Zero-Knowledge şifreleme ile tasarlanmıştır.\nTüm iletişimler yalnızca Eşler Arası (P2P) çalışır.\nMesajlar, güvenli iz bırakmaz bellek temizliği kullanılarak\n24 saat sonra otomatik olarak kendini yok eder.\nSıfır iz, sıfır kayıt, tam gizlilik.',
    'vault_not_initialized_device': 'Kasa bu cihazda başlatılmadı.',
    'invalid_decryption_key': 'Geçersiz Şifre Çözme Anahtarı.',
    'vault_data_corrupted': 'Kasa verileri bozuk (anahtar doğruydu, ancak kasa dosyasının kendisi hasarlı).',
    'decrypt_padlock_title': 'PADLOCK\'UNUZUN ŞİFRESİNİ ÇÖZÜN',
    'login_subtitle': 'ASKERİ DÜZEYDE ZERO-KNOWLEDGE\nŞİFRELEME İLE TASARLANMIŞTIR',
    'enter_decryption_key_label': 'Şifre Çözme Anahtarını Girin',
    'access_vault_button': 'KASAYA ERİŞ',
  },
  'IT': {
    'chats': 'Chat',
    'contacts': 'Contatti',
    'settings': 'Impostazioni',
    'profile': 'Profilo',
    'search_hint': 'Cerca nel database sicuro...',
    'autodestruct': 'Autodistruzione tra',
    'bio_label': 'Bio',
    'bio_text': 'Nodo crittografato P2P / Sicurezza di livello militare',
    'username_label': 'Nome utente',
    'copy_toast': 'ID copiato negli appunti!',
    'qr_title': 'Codice QR privacy',
    'qr_desc': 'Scansiona questo codice per stabilire una connessione P2P sicura.',
    'call': 'Chiamata sicura',
    'new_chat': 'Nuovo canale sicuro',
    'delete_chat': 'Cancella conversazione',
    'block_peer': 'Blocca ID Hex',
    'send_hint': 'Scrivi messaggio crittografato...',
    'custom_sound': 'Suono esclusivo Padlock (Fisso)',
    'silent_mode': 'Modalità silenziosa',
    'notifications': 'Notifiche',
    'sounds_desc': 'Il sistema utilizza toni crittografati esclusivi.',
    'app_lock': 'Blocco con codice',
    'screen_security': 'Blocca screenshot',
    'clear_keys': 'Elimina chiavi di crittografia',
    'keys_purged': 'Tutte le chiavi di sessione sono state distrutte in sicurezza.',
    'offline_contacts': 'Contatti P2P attivi',
    'empty_contacts': 'Nessun contatto rilevato nella rete locale.',
    'language': 'Lingua',
    'search_contact_hint': 'Cerca contatto...',
    'encrypted_p2p_contact': 'Contatto P2P Crittografato',
    'encrypted_p2p_message_preview': '[Messaggio P2P Crittografato]',
    'delete_chat_confirm_title': 'Elimina Conversazione',
    'delete_chat_confirm_body': 'Vuoi eliminare definitivamente questa conversazione?',
    'cancel_button': 'Annulla',
    'delete_button': 'Elimina',
    'settings_header': 'IMPOSTAZIONI',
    'section_core_security': 'Protocolli di Sicurezza Principali',
    'info_encryption_title': 'Crittografia di Livello Militare',
    'info_encryption_desc': 'Standard AES-256-GCM e Curve25519.',
    'info_p2p_title': 'Vero Peer-to-Peer',
    'info_p2p_desc': 'Voce e dati diretti. Zero instradamento tramite server.',
    'info_autodestruct_title': 'Autodistruzione Forense',
    'info_autodestruct_desc': 'Tutti i messaggi vengono distrutti entro un massimo di 24 ore.',
    'info_screenshot_title': 'Protezione Screenshot',
    'info_screenshot_desc': 'La cattura dello schermo è bloccata globalmente in tutta l\'app per prevenire fughe di dati non autorizzate.',
    'info_timeout_title': 'Chiusura Automatica Sicura',
    'info_timeout_desc': 'L\'app si chiude automaticamente dopo 15 minuti di utilizzo, per la tua sicurezza. È necessario effettuare nuovamente l\'accesso per continuare. Le chiamate attive ignorano questa regola per mantenere la connessione.',
    'section_premium': 'Padlock Premium',
    'secure_crypto_vault_title': 'Secure Crypto Vault',
    'crypto_vault_desc': 'Archiviazione di massima sicurezza per i tuoi asset digitali.',
    'section_help_center': 'Centro Assistenza / Come Usare',
    'help_vault_files_q': 'Come usare Secure Vault Files?',
    'help_vault_files_a': 'Per accedere a questa sezione, devi creare una chiave crittografata dedicata. Ogni volta che apri il caveau, ti verrà richiesta questa chiave per accedere, proprio come il login di sicurezza dell\'app.\n\n• Tutte le foto scattate direttamente in Padlock vengono salvate qui automaticamente.\n• Documenti e foto inviati dai contatti al tuo ID vengono indirizzati direttamente a questo caveau invece che alle chat normali. Riceverai una notifica che è stato inviato un contenuto multimediale e dovrai accedervi all\'interno del caveau per visualizzarlo.\n• I file rimangono crittografati e protetti al 100% fino a quando non vengono eliminati, esportati o reinviati manualmente.',
    'help_add_contact_q': 'Come aggiungere un contatto?',
    'help_add_contact_a': 'Vai alla scheda "Contatti", tocca il pulsante blu (+) e incolla un ID Privacy oppure usa lo scanner QR verde.',
    'help_share_id_q': 'Come condividere il mio ID?',
    'help_share_id_a': 'Vai alla scheda "Profilo". Tocca "Copy ID" per incollarlo in sicurezza ovunque, oppure "QR Code" per far scansionare il tuo schermo a qualcuno.',
    'help_rename_contact_q': 'Come rinominare un contatto?',
    'help_rename_contact_a': 'Nella scheda "Contatti", tocca l\'icona Modifica (matita) accanto a un contatto per cambiarne il nome visualizzato.',
    'help_delete_contact_q': 'Come eliminare un contatto?',
    'help_delete_contact_a': 'Nella scheda "Contatti", tieni premuto su un contatto. Questo lo eliminerà definitivamente e distruggerà le chiavi di crittografia condivise.',
    'help_wipe_chat_q': 'Come cancellare una conversazione?',
    'help_wipe_chat_a': 'All\'interno di qualsiasi chat attiva, tocca il menu (tre puntini) in alto a destra e seleziona "Cancella Conversazione" per distruggere tutti i messaggi su entrambi i dispositivi.',
    'section_app_preferences': 'Preferenze App',
    'app_language_title': 'Lingua dell\'App',
    'current_lang_prefix': 'Attuale',
    'silent_mode_desc': 'Disattiva tutte le notifiche e le suonerie delle chiamate.',
    'section_panic_room': 'Stanza del Panico',
    'nuke_vault_title': 'DISTRUGGI CAVEAU: ELIMINA E DISTRUGGI TUTTO',
    'nuke_vault_desc': 'Questa azione distruggerà definitivamente il tuo ID Privacy, i fondi crypto e tutte le chat. Cancella tutto e ti riporta alla schermata di attivazione.',
    'critical_warning_title': 'AVVISO CRITICO',
    'nuke_confirm_body': 'Sei sicuro di voler DISTRUGGERE il caveau?\n\n⚠️ RITIRA TUTTI I FONDI CRYPTO E SALVA I TUOI FILE PRIMA DI PROCEDERE.\n\nQuesta azione è irreversibile. L\'applicazione verrà ripristinata allo stato di fabbrica.',
    'nuke_everything_button': 'DISTRUGGI TUTTO',
    'got_it_button': 'Capito',
    'edit_name_title': 'Nome Modifica',
    'save_button': 'Salva',
    'qr_code_button': 'Codice QR',
    'copy_id_button': 'Copia ID',
    'secure_crypto_vault_short': 'Secure\nCrypto Vault',
    'secure_vault_files_short': 'Secure\nVault Files',
    'privacy_id_label': 'ID Privacy',
    'profile_bio_paragraph': 'Progettato con crittografia Zero-Knowledge di livello militare.\nTutte le comunicazioni funzionano rigorosamente Peer-to-Peer (P2P).\nI messaggi si autodistruggono automaticamente dopo 24 ore\nutilizzando una sanificazione della memoria anti-tracciamento sicura.\nNessuna traccia, nessun registro, privacy totale.',
    'close_button': 'Chiudi',
    'crypto_code_too_weak': 'Il codice è troppo debole: usa almeno 10 caratteri ed evita schemi ripetuti o sequenziali.',
    'invalid_recovery_phrase': 'Frase di recupero non valida - controlla le parole e riprova.',
    'crypto_vault_not_initialized': 'Crypto Vault non inizializzato su questo dispositivo.',
    'invalid_crypto_vault_code': 'Codice Crypto Vault non valido.',
    'crypto_vault_corrupted': 'I dati del Crypto Vault sono corrotti (il codice era corretto, ma il file del caveau stesso è danneggiato).',
    'create_crypto_vault_code_title': 'CREA CODICE CRYPTO VAULT',
    'enter_crypto_vault_code_title': 'INSERISCI CODICE CRYPTO VAULT',
    'crypto_code_desc_create': 'Questo codice è separato dai codici dell\'app e di Vault Files. Protegge un portafoglio nuovo di zecca, non custodial, che controlli solo tu.',
    'crypto_code_desc_enter': 'Inserisci il tuo codice Crypto Vault per accedere al tuo portafoglio.',
    'create_new_wallet_instead': '← Crea invece un nuovo portafoglio',
    'already_have_recovery_phrase': 'Ho già una frase di recupero (telefono perso / reinstallato)',
    'recovery_phrase_label': 'La tua frase di recupero di 12 parole',
    'recovery_phrase_hint': 'parola1 parola2 parola3 ...',
    'set_crypto_vault_code_label': 'Imposta Codice Crypto Vault (per QUESTO dispositivo)',
    'crypto_vault_code_label': 'Codice Crypto Vault',
    'restore_wallet_button': 'RIPRISTINA PORTAFOGLIO',
    'create_wallet_button': 'CREA PORTAFOGLIO',
    'unlock_button': 'SBLOCCA',
    'recovery_phrase_title': 'La Tua Frase di Recupero',
    'recovery_phrase_warning': '⚠️ Scrivi queste 12 parole su carta, in ordine, e conservale in un luogo sicuro e offline. Chiunque abbia queste parole può rubare i tuoi fondi. Padlock NON memorizza questa frase da nessuna parte e non può recuperarla per te.',
    'recovery_phrase_confirm_checkbox': 'Ho scritto queste parole e le ho conservate in sicurezza offline.',
    'continue_button': 'CONTINUA',
    'loading_text': 'Caricamento...',
    'could_not_load_balance': 'Impossibile caricare il saldo',
    'receive_dialog_title': 'Ricevi',
    'receive_address_warning': 'Scansionare o condividere questo codice rivela solo l\'INDIRIZZO del tuo portafoglio - mai la tua frase di recupero.',
    'address_copied_toast': 'Indirizzo copiato.',
    'copy_button': 'COPIA',
    'testnet_warning': '⚠️ RETE DI TEST (Polygon Amoy) - questi NON sono fondi reali.',
    'balances_label': 'Saldi',
    'receive_button': 'RICEVI',
    'send_button': 'INVIA',
    'camera_permission_denied': 'Permesso fotocamera negato. Attivalo in Impostazioni telefono > App > Padlock > Autorizzazioni.',
    'scan_wallet_address_title': 'Scansiona Indirizzo Portafoglio',
    'invalid_wallet_address': 'Indirizzo del portafoglio non valido.',
    'enter_valid_amount': 'Inserisci un importo valido.',
    'price_not_loaded': 'Quotazione non ancora caricata - riprova tra un momento.',
    'transaction_sent_title': 'Transazione Inviata',
    'done_button': 'FATTO',
    'send_failed_prefix': 'Invio non riuscito',
    'send_title': 'Invia',
    'recipient_address_label': 'Indirizzo del portafoglio del destinatario',
    'coin_label': 'Moneta',
    'amount_in_label': 'Importo in:',
    'amount_usd_label': 'Importo (USD)',
    'amount_label_prefix': 'Importo',
    'loading_price': 'Caricamento quotazione...',
    'price_label_prefix': 'Quotazione',
    'confirm_send_button': 'CONFERMA E INVIA',
    'vault_files_not_initialized': 'Vault Files non è inizializzato su questo dispositivo.',
    'invalid_vault_files_code': 'Codice Vault Files non valido.',
    'vault_files_corrupted': 'I dati di Vault Files sono danneggiati (il codice era corretto, ma il file del caveau stesso è danneggiato).',
    'create_vault_files_code_title': 'CREA CODICE VAULT FILES',
    'enter_vault_files_code_title': 'INSERISCI CODICE VAULT FILES',
    'vault_files_code_desc_create': 'Questo codice è separato dal codice di sblocco dell\'app. Chi conosce il codice dell\'app NON potrà aprire le tue foto e i tuoi documenti senza anche questo codice.',
    'vault_files_code_desc_enter': 'Inserisci il tuo codice Vault Files per visualizzare le tue foto e i tuoi documenti crittografati.',
    'set_vault_files_code_label': 'Imposta Codice Vault Files',
    'vault_files_code_label': 'Codice Vault Files',
    'create_vault_button': 'CREA CAVEAU',
    'imported_skipped_toast': '{imported} importati, {skipped} saltati (max {mb}MB ciascuno).',
    'no_contacts_yet': 'Nessun contatto ancora.',
    'send_to_title': 'Invia a...',
    'sent_toast': 'Inviato.',
    'failed_to_send_prefix': 'Invio non riuscito',
    'received_from_prefix': 'Ricevuto da',
    'sent_to_prefix': 'Inviato a',
    'stored_locally_not_sent': 'Salvato localmente — non ancora inviato a nessuno',
    'document_label': 'Documento',
    'document_stored_encrypted_desc': 'Questo documento è salvato crittografato nel tuo Vault Files ({kb} KB). Usa Esporta per salvarlo di nuovo sul telefono o condividerlo.',
    'export_button': 'Esporta',
    'personal_files_empty': 'Nessun file personale ancora.\nUsa il pulsante + per scattare una foto o importare un documento.',
    'received_files_empty': 'Ancora nulla ricevuto.',
    'sent_files_empty': 'Ancora nulla inviato.',
    'tab_personal': 'Personale',
    'tab_received': 'Ricevuti',
    'tab_sent': 'Inviati',
    'copy_message': 'Copia Messaggio',
    'destroy_message': 'Distruggi Messaggio',
    'node_destruction_title': 'Distruzione del Nodo',
    'destroy_message_confirm_body': 'Vuoi distruggere definitivamente questo messaggio su entrambi i dispositivi?',
    'destroy_button': 'Distruggi',
    'failed_to_send_photo_prefix': 'Invio foto non riuscito',
    'encrypted_photo_sent_message': '🖼️ Foto crittografata inviata — visualizzala in Secure Vault Files',
    'photo_chat_preview': '🖼️ Foto',
    'just_now': 'Proprio ora',
    'failed_to_send_voice_prefix': 'Invio messaggio vocale non riuscito',
    'voice_message_chat_preview': '🎤 Messaggio vocale',
    'voice_message_label': 'Messaggio vocale',
    'no_secure_channel_error': 'Impossibile inviare: non c\'è ancora un canale sicuro con questo contatto ({error}). Prova a rimuoverlo e riaggiungerlo.',
    'block_id_title': 'Blocca ID',
    'block_id_confirm_body': 'Vuoi bloccare definitivamente questo ID?',
    'block_button': 'Blocca',
    'keys_not_available': 'Chiavi non disponibili per questo contatto.',
    'safety_number_title': 'Numero di Sicurezza',
    'safety_number_desc': 'Effettua una chiamata sicura a questo contatto e leggi ad alta voce questo numero. Se corrisponde su entrambi i dispositivi, nessuno sta intercettando la tua conversazione.',
    'verify_safety_number': 'Verifica Numero di Sicurezza',
    'encrypted_p2p_channel': 'Canale P2P Crittografato',
    'destruct_1m': '1 Minuto',
    'destruct_5m': '5 Minuti',
    'destruct_1h': '1 Ora',
    'destruct_24h': '24 Ore',
    'message_not_decrypted': '[Messaggio non decifrato]',
    'call_status_connecting': 'Connessione...',
    'call_status_exchanging_keys': 'Scambio delle chiavi di crittografia...',
    'call_status_ringing': 'Squillo...',
    'call_status_connecting_encrypted': 'Connessione chiamata crittografata...',
    'call_status_incoming_encrypted': 'Chiamata crittografata in arrivo...',
    'call_status_connected_prefix': 'Connesso',
    'call_status_connected_encrypted': 'Connesso e crittografato',
    'call_status_reconnecting': 'Riconnessione...',
    'call_contact_unavailable': 'Contatto non disponibile o offline.',
    'missed_secure_call': 'Chiamata Sicura Persa',
    'missed_call_notification_title': 'Chiamata Persa',
    'setup_code_too_weak': 'La chiave di decrittazione è troppo debole: usa almeno 10 caratteri ed evita schemi ripetuti o sequenziali.',
    'vault_init_failed_prefix': 'Inizializzazione del caveau non riuscita',
    'create_vault_title': 'CREA IL TUO CAVEAU CRITTOGRAFATO',
    'create_vault_subtitle': 'Imposta la tua chiave principale per generare\nla tua identità crittografica P2P',
    'set_decryption_key_label': 'Imposta Chiave di Decrittazione',
    'strength_too_weak': 'Troppo debole',
    'strength_weak': 'Debole',
    'strength_medium': 'Media',
    'strength_strong': 'Forte',
    'strength_very_strong': 'Molto forte',
    'initialize_vault_button': 'INIZIALIZZA CAVEAU',
    'footer_privacy_text': 'Progettato con crittografia Zero-Knowledge di livello militare.\nTutte le comunicazioni operano strettamente Peer-to-Peer (P2P).\nI messaggi si autodistruggono automaticamente dopo 24 ore\nutilizzando una sanificazione sicura della memoria anti-traccia.\nZero tracce, zero log, privacy totale.',
    'vault_not_initialized_device': 'Caveau non inizializzato su questo dispositivo.',
    'invalid_decryption_key': 'Chiave di Decrittazione non valida.',
    'vault_data_corrupted': 'I dati del caveau sono danneggiati (la chiave era corretta, ma il file del caveau stesso è danneggiato).',
    'decrypt_padlock_title': 'DECIFRA IL TUO PADLOCK',
    'login_subtitle': 'PROGETTATO CON CRITTOGRAFIA ZERO-KNOWLEDGE\nDI LIVELLO MILITARE',
    'enter_decryption_key_label': 'Inserisci Chiave di Decrittazione',
    'access_vault_button': 'ACCEDI AL CAVEAU',
  },
  'JA': {
    'chats': 'チャット',
    'contacts': '連絡先',
    'settings': '設定',
    'profile': 'プロフィール',
    'search_hint': 'セキュアデータベースを検索...',
    'autodestruct': '自動削除まで',
    'bio_label': '自己紹介',
    'bio_text': 'P2P暗号化ノード / 軍事レベルのセキュリティ',
    'username_label': 'ユーザー名',
    'copy_toast': 'IDをクリップボードにコピーしました！',
    'qr_title': 'プライバシーQRコード',
    'qr_desc': 'このコードをスキャンして、安全なP2P接続を確立します。',
    'call': 'セキュア通話',
    'new_chat': '新しいセキュアチャンネル',
    'delete_chat': '会話を削除',
    'block_peer': 'Hex IDをブロック',
    'send_hint': '暗号化メッセージを入力...',
    'custom_sound': 'Padlock専用サウンド（固定）',
    'silent_mode': 'サイレントモード',
    'notifications': '通知',
    'sounds_desc': 'システムは専用の暗号化トーンを使用します。',
    'app_lock': 'パスコードロック',
    'screen_security': 'スクリーンショットをブロック',
    'clear_keys': '暗号化キーを削除',
    'keys_purged': 'すべてのセッションキーが安全に破棄されました。',
    'offline_contacts': 'アクティブなP2P連絡先',
    'empty_contacts': 'ローカルネットワークで連絡先が見つかりません。',
    'language': '言語',
    'search_contact_hint': '連絡先を検索...',
    'encrypted_p2p_contact': '暗号化されたP2P連絡先',
    'encrypted_p2p_message_preview': '[暗号化されたP2Pメッセージ]',
    'delete_chat_confirm_title': '会話を削除',
    'delete_chat_confirm_body': 'この会話を完全に削除しますか？',
    'cancel_button': 'キャンセル',
    'delete_button': '削除',
    'settings_header': '設定',
    'section_core_security': '中核セキュリティプロトコル',
    'info_encryption_title': '軍事レベルの暗号化',
    'info_encryption_desc': 'AES-256-GCM および Curve25519 標準。',
    'info_p2p_title': '真のピアツーピア',
    'info_p2p_desc': '直接的な音声とデータ。サーバー経由のルーティングなし。',
    'info_autodestruct_title': 'フォレンジック自動削除',
    'info_autodestruct_desc': 'すべてのメッセージは最大24時間以内に破棄されます。',
    'info_screenshot_title': 'スクリーンショット保護',
    'info_screenshot_desc': '不正なデータ漏洩を防ぐため、アプリ全体で画面キャプチャがブロックされます。',
    'info_timeout_title': '安全タイムアウト',
    'info_timeout_desc': 'セキュリティのため、15分間使用するとアプリは自動的に終了します。再開するには再ログインが必要です。通話中はこのルールが適用されず、接続が維持されます。',
    'section_premium': 'Padlock Premium',
    'secure_crypto_vault_title': 'Secure Crypto Vault',
    'crypto_vault_desc': 'デジタル資産のための最高セキュリティのストレージ。',
    'section_help_center': 'ヘルプセンター / 使い方',
    'help_vault_files_q': 'Secure Vault Filesの使い方は？',
    'help_vault_files_a': 'このセクションにアクセスするには、専用の暗号化キーを作成する必要があります。保管庫を開くたびに、アプリのセキュリティログインと同様にこのキーの入力が求められます。\n\n• Padlock内で直接撮影したすべての写真は自動的にここに保存されます。\n• 連絡先からあなたのIDに送信されたドキュメントや写真は、通常のチャットではなく直接この保管庫に送られます。メディアが送信されたという通知が届き、閲覧するには保管庫内でアクセスする必要があります。\n• ファイルは手動で削除、エクスポート、または再送信されるまで100%暗号化され安全に保たれます。',
    'help_add_contact_q': '連絡先の追加方法は？',
    'help_add_contact_a': '「連絡先」タブに移動し、青い（+）ボタンをタップして、プライバシーIDを貼り付けるか、緑のQRスキャナーを使用してください。',
    'help_share_id_q': '自分のIDを共有する方法は？',
    'help_share_id_a': '「プロフィール」タブに移動します。「Copy ID」をタップしてどこにでも安全に貼り付けるか、「QR Code」をタップして誰かに画面をスキャンしてもらいます。',
    'help_rename_contact_q': '連絡先の名前を変更する方法は？',
    'help_rename_contact_a': '「連絡先」タブで、連絡先の横にある編集（鉛筆）アイコンをタップして表示名を変更します。',
    'help_delete_contact_q': '連絡先を削除する方法は？',
    'help_delete_contact_a': '「連絡先」タブで、任意の連絡先を長押しします。これにより連絡先が完全に削除され、共有暗号化キーが破棄されます。',
    'help_wipe_chat_q': '会話を削除する方法は？',
    'help_wipe_chat_a': 'アクティブなチャット内で、右上のメニュー（三点）をタップし、「会話を削除」を選択して両方のデバイスのすべてのメッセージを破棄します。',
    'section_app_preferences': 'アプリ設定',
    'app_language_title': 'アプリの言語',
    'current_lang_prefix': '現在',
    'silent_mode_desc': 'すべての通知と着信音をミュートします。',
    'section_panic_room': 'パニックルーム',
    'nuke_vault_title': 'ボールト消去：すべてを消去して破棄',
    'nuke_vault_desc': 'この操作は、プライバシーID、暗号資産、すべてのチャットを完全に破棄します。すべてを消去してアクティベーション画面に戻ります。',
    'critical_warning_title': '重大な警告',
    'nuke_confirm_body': '本当にボールトを消去しますか？\n\n⚠️ 続行する前に、すべての暗号資産を引き出し、ファイルを保存してください。\n\nこの操作は元に戻せません。アプリケーションは工場出荷状態にリセットされます。',
    'nuke_everything_button': 'すべて破棄',
    'got_it_button': '了解',
    'edit_name_title': '名前を編集',
    'save_button': '保存',
    'qr_code_button': 'QRコード',
    'copy_id_button': 'IDをコピー',
    'secure_crypto_vault_short': 'Secure\nCrypto Vault',
    'secure_vault_files_short': 'Secure\nVault Files',
    'privacy_id_label': 'プライバシーID',
    'profile_bio_paragraph': '軍事レベルのゼロ知識暗号化で構築。\nすべての通信は厳密にピアツーピア（P2P）で動作します。\nメッセージは安全な追跡防止メモリ消去技術を使用して24時間後に自動的に自己破棄されます。\n痕跡ゼロ、ログゼロ、完全なプライバシー。',
    'close_button': '閉じる',
    'crypto_code_too_weak': 'コードが弱すぎます：少なくとも10文字を使用し、繰り返しや連続したパターンを避けてください。',
    'invalid_recovery_phrase': 'リカバリーフレーズが無効です - 単語を確認して再試行してください。',
    'crypto_vault_not_initialized': 'このデバイスでCrypto Vaultが初期化されていません。',
    'invalid_crypto_vault_code': 'Crypto Vaultコードが無効です。',
    'crypto_vault_corrupted': 'Crypto Vaultのデータが破損しています（コードは正しいですが、保管庫ファイル自体が破損しています）。',
    'create_crypto_vault_code_title': 'CRYPTO VAULTコードを作成',
    'enter_crypto_vault_code_title': 'CRYPTO VAULTコードを入力',
    'crypto_code_desc_create': 'このコードはアプリやVault Filesのコードとは別です。あなただけが管理する、まったく新しい非管理型ウォレットを保護します。',
    'crypto_code_desc_enter': 'ウォレットにアクセスするにはCrypto Vaultコードを入力してください。',
    'create_new_wallet_instead': '← 代わりに新しいウォレットを作成',
    'already_have_recovery_phrase': 'すでにリカバリーフレーズを持っています（携帯電話を紛失/再インストール）',
    'recovery_phrase_label': '12語のリカバリーフレーズ',
    'recovery_phrase_hint': '単語1 単語2 単語3 ...',
    'set_crypto_vault_code_label': 'Crypto Vaultコードを設定（このデバイス用）',
    'crypto_vault_code_label': 'Crypto Vaultコード',
    'restore_wallet_button': 'ウォレットを復元',
    'create_wallet_button': 'ウォレットを作成',
    'unlock_button': 'ロック解除',
    'recovery_phrase_title': 'リカバリーフレーズ',
    'recovery_phrase_warning': '⚠️ この12語を順番に紙に書き留め、安全なオフラインの場所に保管してください。これらの単語を持つ人は誰でもあなたの資金を盗むことができます。Padlockはこのフレーズをどこにも保存せず、あなたのために復元することはできません。',
    'recovery_phrase_confirm_checkbox': 'これらの単語を書き留め、安全にオフラインで保管しました。',
    'continue_button': '続ける',
    'loading_text': '読み込み中...',
    'could_not_load_balance': '残高を読み込めませんでした',
    'receive_dialog_title': '受け取る',
    'receive_address_warning': 'このコードをスキャンまたは共有すると、ウォレットのアドレスのみが公開されます - リカバリーフレーズは決して公開されません。',
    'address_copied_toast': 'アドレスをコピーしました。',
    'copy_button': 'コピー',
    'testnet_warning': '⚠️ テストネット（Polygon Amoy）- これらは実際の資金ではありません。',
    'balances_label': '残高',
    'receive_button': '受け取る',
    'send_button': '送る',
    'camera_permission_denied': 'カメラの許可が拒否されました。電話の設定 > アプリ > Padlock > 権限で有効にしてください。',
    'scan_wallet_address_title': 'ウォレットアドレスをスキャン',
    'invalid_wallet_address': 'ウォレットアドレスが無効です。',
    'enter_valid_amount': '有効な金額を入力してください。',
    'price_not_loaded': '価格がまだ読み込まれていません - 少し待ってから再試行してください。',
    'transaction_sent_title': '取引送信済み',
    'done_button': '完了',
    'send_failed_prefix': '送信失敗',
    'send_title': '送る',
    'recipient_address_label': '受取人のウォレットアドレス',
    'coin_label': 'コイン',
    'amount_in_label': '金額の単位：',
    'amount_usd_label': '金額（USD）',
    'amount_label_prefix': '金額',
    'loading_price': '価格を読み込み中...',
    'price_label_prefix': '価格',
    'confirm_send_button': '確認して送信',
    'vault_files_not_initialized': 'この端末では Vault Files が初期化されていません。',
    'invalid_vault_files_code': 'Vault Files コードが無効です。',
    'vault_files_corrupted': 'Vault Files のデータが破損しています(コードは正しいですが、金庫ファイル自体が破損しています)。',
    'create_vault_files_code_title': 'VAULT FILES コードを作成',
    'enter_vault_files_code_title': 'VAULT FILES コードを入力',
    'vault_files_code_desc_create': 'このコードはアプリのロック解除コードとは別のものです。アプリのコードを知っている人でも、このコードなしでは写真や書類を開くことができません。',
    'vault_files_code_desc_enter': '暗号化された写真や書類を表示するには、Vault Files コードを入力してください。',
    'set_vault_files_code_label': 'Vault Files コードを設定',
    'vault_files_code_label': 'Vault Files コード',
    'create_vault_button': '金庫を作成',
    'imported_skipped_toast': '{imported} 件をインポート、{skipped} 件をスキップ(それぞれ最大 {mb}MB)。',
    'no_contacts_yet': 'まだ連絡先がありません。',
    'send_to_title': '送信先...',
    'sent_toast': '送信しました。',
    'failed_to_send_prefix': '送信に失敗しました',
    'received_from_prefix': '送信元',
    'sent_to_prefix': '送信先',
    'stored_locally_not_sent': 'ローカルに保存済み — まだ誰にも送信されていません',
    'document_label': '書類',
    'document_stored_encrypted_desc': 'この書類は Vault Files に暗号化されて保存されています({kb} KB)。エクスポートを使って端末に保存し直したり、共有したりできます。',
    'export_button': 'エクスポート',
    'personal_files_empty': 'まだ個人ファイルがありません。\n+ ボタンを使って写真を撮るか、書類をインポートしてください。',
    'received_files_empty': 'まだ何も受信していません。',
    'sent_files_empty': 'まだ何も送信していません。',
    'tab_personal': '個人',
    'tab_received': '受信済み',
    'tab_sent': '送信済み',
    'copy_message': 'メッセージをコピー',
    'destroy_message': 'メッセージを破棄',
    'node_destruction_title': 'ノードの破棄',
    'destroy_message_confirm_body': 'このメッセージを両方の端末で完全に破棄しますか?',
    'destroy_button': '破棄',
    'failed_to_send_photo_prefix': '写真の送信に失敗しました',
    'encrypted_photo_sent_message': '🖼️ 暗号化された写真を送信しました — Secure Vault Files で確認してください',
    'photo_chat_preview': '🖼️ 写真',
    'just_now': 'たった今',
    'failed_to_send_voice_prefix': 'ボイスメッセージの送信に失敗しました',
    'voice_message_chat_preview': '🎤 ボイスメッセージ',
    'voice_message_label': 'ボイスメッセージ',
    'no_secure_channel_error': '送信できませんでした:この連絡先とはまだ安全な通信経路がありません({error})。削除してから再度追加してみてください。',
    'block_id_title': 'IDをブロック',
    'block_id_confirm_body': 'このIDを完全にブロックしますか?',
    'block_button': 'ブロック',
    'keys_not_available': 'この連絡先の鍵が利用できません。',
    'safety_number_title': '安全番号',
    'safety_number_desc': 'この連絡先と安全な通話を行い、この番号を声に出して読み上げてください。両方の端末で一致すれば、誰も会話を傍受していません。',
    'verify_safety_number': '安全番号を確認',
    'encrypted_p2p_channel': '暗号化された P2P チャネル',
    'destruct_1m': '1分',
    'destruct_5m': '5分',
    'destruct_1h': '1時間',
    'destruct_24h': '24時間',
    'message_not_decrypted': '[メッセージを復号できませんでした]',
    'call_status_connecting': '接続中...',
    'call_status_exchanging_keys': '暗号鍵を交換中...',
    'call_status_ringing': '呼び出し中...',
    'call_status_connecting_encrypted': '暗号化通話を接続中...',
    'call_status_incoming_encrypted': '暗号化された着信通話...',
    'call_status_connected_prefix': '接続済み',
    'call_status_connected_encrypted': '接続され暗号化されています',
    'call_status_reconnecting': '再接続中...',
    'call_contact_unavailable': '連絡先が利用できないかオフラインです。',
    'missed_secure_call': '不在着信(セキュア通話)',
    'missed_call_notification_title': '不在着信',
    'setup_code_too_weak': '復号鍵が弱すぎます。10文字以上を使用し、繰り返しや連続したパターンは避けてください。',
    'vault_init_failed_prefix': 'ボールトの初期化に失敗しました',
    'create_vault_title': '暗号化ボールトを作成',
    'create_vault_subtitle': 'マスターキーを設定して\nP2P暗号アイデンティティを生成します',
    'set_decryption_key_label': '復号鍵を設定',
    'strength_too_weak': '弱すぎる',
    'strength_weak': '弱い',
    'strength_medium': '普通',
    'strength_strong': '強い',
    'strength_very_strong': '非常に強い',
    'initialize_vault_button': 'ボールトを初期化',
    'footer_privacy_text': '軍事レベルのゼロ知識暗号化で設計されています。\nすべての通信は厳密にピアツーピア(P2P)で動作します。\nメッセージは安全な痕跡防止メモリ消去により\n24時間後に自動的に自壊します。\n痕跡ゼロ、ログゼロ、完全なプライバシー。',
    'vault_not_initialized_device': 'この端末ではボールトが初期化されていません。',
    'invalid_decryption_key': '復号鍵が無効です。',
    'vault_data_corrupted': 'ボールトのデータが破損しています(鍵は正しいですが、ボールトファイル自体が破損しています)。',
    'decrypt_padlock_title': 'PADLOCKを復号',
    'login_subtitle': '軍事レベルのゼロ知識暗号化で設計されています',
    'enter_decryption_key_label': '復号鍵を入力',
    'access_vault_button': 'ボールトにアクセス',
  },
  'HI': {
    'chats': 'चैट',
    'contacts': 'संपर्क',
    'settings': 'सेटिंग्स',
    'profile': 'प्रोफ़ाइल',
    'search_hint': 'सुरक्षित डेटाबेस खोजें...',
    'autodestruct': 'स्वतः नष्ट होने का समय',
    'bio_label': 'बायो',
    'bio_text': 'P2P एन्क्रिप्टेड नोड / सैन्य-स्तर की सुरक्षा',
    'username_label': 'उपयोगकर्ता नाम',
    'copy_toast': 'आईडी क्लिपबोर्ड पर कॉपी हो गई!',
    'qr_title': 'गोपनीयता QR कोड',
    'qr_desc': 'सुरक्षित P2P कनेक्शन स्थापित करने के लिए इस कोड को स्कैन करें।',
    'call': 'सुरक्षित कॉल',
    'new_chat': 'नया सुरक्षित चैनल',
    'delete_chat': 'बातचीत मिटाएं',
    'block_peer': 'Hex ID ब्लॉक करें',
    'send_hint': 'एन्क्रिप्टेड संदेश लिखें...',
    'custom_sound': 'Padlock विशेष ध्वनि (निश्चित)',
    'silent_mode': 'साइलेंट मोड',
    'notifications': 'सूचनाएं',
    'sounds_desc': 'सिस्टम विशेष एन्क्रिप्टेड टोन का उपयोग करता है।',
    'app_lock': 'पासकोड लॉक',
    'screen_security': 'स्क्रीनशॉट ब्लॉक करें',
    'clear_keys': 'एन्क्रिप्शन कुंजियाँ हटाएं',
    'keys_purged': 'सभी सत्र कुंजियाँ सुरक्षित रूप से नष्ट कर दी गई हैं।',
    'offline_contacts': 'सक्रिय P2P संपर्क',
    'empty_contacts': 'स्थानीय नेटवर्क में कोई संपर्क नहीं मिला।',
    'language': 'भाषा',
    'search_contact_hint': 'संपर्क खोजें...',
    'encrypted_p2p_contact': 'एन्क्रिप्टेड P2P संपर्क',
    'encrypted_p2p_message_preview': '[एन्क्रिप्टेड P2P संदेश]',
    'delete_chat_confirm_title': 'बातचीत हटाएं',
    'delete_chat_confirm_body': 'क्या आप इस बातचीत को स्थायी रूप से हटाना चाहते हैं?',
    'cancel_button': 'रद्द करें',
    'delete_button': 'हटाएं',
    'settings_header': 'सेटिंग्स',
    'section_core_security': 'मुख्य सुरक्षा प्रोटोकॉल',
    'info_encryption_title': 'सैन्य-स्तर की एन्क्रिप्शन',
    'info_encryption_desc': 'AES-256-GCM और Curve25519 मानक।',
    'info_p2p_title': 'सच्चा पीयर-टू-पीयर',
    'info_p2p_desc': 'प्रत्यक्ष आवाज़ और डेटा। शून्य सर्वर रूटिंग।',
    'info_autodestruct_title': 'फोरेंसिक ऑटो-डिस्ट्रक्ट',
    'info_autodestruct_desc': 'सभी संदेश अधिकतम 24 घंटे के भीतर नष्ट हो जाते हैं।',
    'info_screenshot_title': 'स्क्रीनशॉट सुरक्षा',
    'info_screenshot_desc': 'अनधिकृत डेटा लीक को रोकने के लिए ऐप में स्क्रीन कैप्चर पूरी तरह से अवरुद्ध है।',
    'info_timeout_title': 'सुरक्षित टाइमआउट',
    'info_timeout_desc': 'आपकी सुरक्षा के लिए 15 मिनट के उपयोग के बाद ऐप स्वतः बंद हो जाता है। जारी रखने के लिए फिर से लॉगिन आवश्यक है। सक्रिय कॉल कनेक्शन बनाए रखने के लिए इस नियम को नज़रअंदाज़ करती हैं।',
    'section_premium': 'Padlock Premium',
    'secure_crypto_vault_title': 'Secure Crypto Vault',
    'crypto_vault_desc': 'आपकी डिजिटल संपत्तियों के लिए अधिकतम सुरक्षा भंडारण।',
    'section_help_center': 'सहायता केंद्र / उपयोग कैसे करें',
    'help_vault_files_q': 'Secure Vault Files का उपयोग कैसे करें?',
    'help_vault_files_a': 'इस सेक्शन तक पहुंचने के लिए, आपको एक समर्पित एन्क्रिप्टेड कुंजी बनानी होगी। जब भी आप वॉल्ट खोलेंगे, यह लॉगिन के लिए यह कुंजी मांगेगा, बिल्कुल ऐप सुरक्षा लॉगिन की तरह।\n\n• Padlock के भीतर सीधे ली गई सभी तस्वीरें यहां स्वतः सहेजी जाती हैं।\n• संपर्कों द्वारा आपके ID पर भेजे गए दस्तावेज़ और तस्वीरें सामान्य चैट के बजाय सीधे इस वॉल्ट में भेजी जाती हैं। आपको मीडिया भेजे जाने की सूचना मिलेगी, और देखने के लिए आपको वॉल्ट के अंदर जाना होगा।\n• फ़ाइलें मैन्युअल रूप से हटाए, निर्यात या पुनः भेजे जाने तक 100% एन्क्रिप्टेड और सुरक्षित रहती हैं।',
    'help_add_contact_q': 'संपर्क कैसे जोड़ें?',
    'help_add_contact_a': '"संपर्क" टैब पर जाएं, नीले (+) बटन पर टैप करें, और एक गोपनीयता ID पेस्ट करें या हरे QR स्कैनर का उपयोग करें।',
    'help_share_id_q': 'अपनी ID कैसे साझा करें?',
    'help_share_id_a': '"प्रोफ़ाइल" टैब पर जाएं। इसे कहीं भी सुरक्षित रूप से पेस्ट करने के लिए "Copy ID" पर टैप करें, या किसी को अपनी स्क्रीन स्कैन करने देने के लिए "QR Code" पर टैप करें।',
    'help_rename_contact_q': 'किसी संपर्क का नाम कैसे बदलें?',
    'help_rename_contact_a': '"संपर्क" टैब में, प्रदर्शित नाम बदलने के लिए किसी भी संपर्क के बगल में संपादन (पेंसिल) आइकन पर टैप करें।',
    'help_delete_contact_q': 'किसी संपर्क को कैसे हटाएं?',
    'help_delete_contact_a': '"संपर्क" टैब में, किसी भी संपर्क को दबाकर रखें। इससे वह स्थायी रूप से हट जाएगा और साझा एन्क्रिप्शन कुंजियाँ नष्ट हो जाएंगी।',
    'help_wipe_chat_q': 'बातचीत कैसे मिटाएं?',
    'help_wipe_chat_a': 'किसी भी सक्रिय चैट में, ऊपरी दाएं कोने में मेनू (तीन डॉट्स) पर टैप करें और दोनों डिवाइस पर सभी संदेशों को नष्ट करने के लिए "बातचीत मिटाएं" चुनें।',
    'section_app_preferences': 'ऐप प्राथमिकताएं',
    'app_language_title': 'ऐप भाषा',
    'current_lang_prefix': 'वर्तमान',
    'silent_mode_desc': 'सभी सूचनाओं और कॉल रिंगटोन को म्यूट करता है।',
    'section_panic_room': 'पैनिक रूम',
    'nuke_vault_title': 'वॉल्ट नष्ट करें: सब कुछ मिटाएं और नष्ट करें',
    'nuke_vault_desc': 'यह क्रिया आपकी गोपनीयता ID, क्रिप्टो फंड और सभी चैट को स्थायी रूप से नष्ट कर देगी। यह सब कुछ साफ़ कर देती है और आपको सक्रियण स्क्रीन पर वापस भेज देती है।',
    'critical_warning_title': 'गंभीर चेतावनी',
    'nuke_confirm_body': 'क्या आप वाकई वॉल्ट को नष्ट करना चाहते हैं?\n\n⚠️ आगे बढ़ने से पहले सभी क्रिप्टो फंड निकालें और अपनी फ़ाइलें सहेजें।\n\nयह क्रिया अपरिवर्तनीय है। एप्लिकेशन फ़ैक्टरी स्थिति में रीसेट हो जाएगा।',
    'nuke_everything_button': 'सब कुछ नष्ट करें',
    'got_it_button': 'समझ गया',
    'edit_name_title': 'नाम संपादित करें',
    'save_button': 'सहेजें',
    'qr_code_button': 'QR कोड',
    'copy_id_button': 'ID कॉपी करें',
    'secure_crypto_vault_short': 'Secure\nCrypto Vault',
    'secure_vault_files_short': 'Secure\nVault Files',
    'privacy_id_label': 'गोपनीयता ID',
    'profile_bio_paragraph': 'सैन्य-स्तर की ज़ीरो-नॉलेज एन्क्रिप्शन के साथ बनाया गया।\nसभी संचार सख्ती से पीयर-टू-पीयर (P2P) पर काम करते हैं।\nसंदेश सुरक्षित एंटी-ट्रेस मेमोरी सैनिटाइजेशन का उपयोग करके 24 घंटे बाद स्वतः नष्ट हो जाते हैं।\nशून्य निशान, शून्य लॉग, पूर्ण गोपनीयता।',
    'close_button': 'बंद करें',
    'crypto_code_too_weak': 'कोड बहुत कमज़ोर है: कम से कम 10 अक्षरों का उपयोग करें और दोहराए जाने वाले या क्रमिक पैटर्न से बचें।',
    'invalid_recovery_phrase': 'अमान्य रिकवरी फ्रेज़ - शब्दों की जाँच करें और फिर से प्रयास करें।',
    'crypto_vault_not_initialized': 'इस डिवाइस पर Crypto Vault प्रारंभ नहीं किया गया है।',
    'invalid_crypto_vault_code': 'अमान्य Crypto Vault कोड।',
    'crypto_vault_corrupted': 'Crypto Vault डेटा दूषित है (कोड सही था, लेकिन वॉल्ट फ़ाइल स्वयं क्षतिग्रस्त है)।',
    'create_crypto_vault_code_title': 'CRYPTO VAULT कोड बनाएं',
    'enter_crypto_vault_code_title': 'CRYPTO VAULT कोड दर्ज करें',
    'crypto_code_desc_create': 'यह कोड आपके ऐप और Vault Files कोड से अलग है। यह एक बिल्कुल नए, गैर-कस्टोडियल वॉलेट की रक्षा करता है जिसे केवल आप नियंत्रित करते हैं।',
    'crypto_code_desc_enter': 'अपने वॉलेट तक पहुंचने के लिए अपना Crypto Vault कोड दर्ज करें।',
    'create_new_wallet_instead': '← इसके बजाय एक नया वॉलेट बनाएं',
    'already_have_recovery_phrase': 'मेरे पास पहले से ही एक रिकवरी फ्रेज़ है (फोन खो गया / पुनः स्थापित किया)',
    'recovery_phrase_label': 'आपका 12-शब्द रिकवरी फ्रेज़',
    'recovery_phrase_hint': 'शब्द1 शब्द2 शब्द3 ...',
    'set_crypto_vault_code_label': 'Crypto Vault कोड सेट करें (इस डिवाइस के लिए)',
    'crypto_vault_code_label': 'Crypto Vault कोड',
    'restore_wallet_button': 'वॉलेट पुनर्स्थापित करें',
    'create_wallet_button': 'वॉलेट बनाएं',
    'unlock_button': 'अनलॉक करें',
    'recovery_phrase_title': 'आपका रिकवरी फ्रेज़',
    'recovery_phrase_warning': '⚠️ इन 12 शब्दों को क्रम में कागज़ पर लिखें, और उन्हें कहीं सुरक्षित और ऑफ़लाइन रखें। इन शब्दों वाला कोई भी व्यक्ति आपका धन चुरा सकता है। Padlock इस फ्रेज़ को कहीं भी संग्रहीत नहीं करता और आपके लिए इसे पुनर्प्राप्त नहीं कर सकता।',
    'recovery_phrase_confirm_checkbox': 'मैंने ये शब्द लिख लिए हैं और उन्हें सुरक्षित रूप से ऑफ़लाइन संग्रहीत कर लिया है।',
    'continue_button': 'जारी रखें',
    'loading_text': 'लोड हो रहा है...',
    'could_not_load_balance': 'बैलेंस लोड नहीं हो सका',
    'receive_dialog_title': 'प्राप्त करें',
    'receive_address_warning': 'इस कोड को स्कैन या साझा करने से केवल आपके वॉलेट का पता ही मिलता है - कभी भी आपका रिकवरी फ्रेज़ नहीं।',
    'address_copied_toast': 'पता कॉपी किया गया।',
    'copy_button': 'कॉपी करें',
    'testnet_warning': '⚠️ टेस्टनेट (Polygon Amoy) - ये वास्तविक धनराशि नहीं हैं।',
    'balances_label': 'बैलेंस',
    'receive_button': 'प्राप्त करें',
    'send_button': 'भेजें',
    'camera_permission_denied': 'कैमरा अनुमति अस्वीकृत। फ़ोन सेटिंग्स > ऐप्स > Padlock > अनुमतियों में इसे सक्षम करें।',
    'scan_wallet_address_title': 'वॉलेट पता स्कैन करें',
    'invalid_wallet_address': 'अमान्य वॉलेट पता।',
    'enter_valid_amount': 'एक वैध राशि दर्ज करें।',
    'price_not_loaded': 'कीमत अभी लोड नहीं हुई - कुछ देर बाद फिर से प्रयास करें।',
    'transaction_sent_title': 'लेनदेन भेजा गया',
    'done_button': 'हो गया',
    'send_failed_prefix': 'भेजना विफल',
    'send_title': 'भेजें',
    'recipient_address_label': 'प्राप्तकर्ता का वॉलेट पता',
    'coin_label': 'कॉइन',
    'amount_in_label': 'राशि इकाई:',
    'amount_usd_label': 'राशि (USD)',
    'amount_label_prefix': 'राशि',
    'loading_price': 'कीमत लोड हो रही है...',
    'price_label_prefix': 'कीमत',
    'confirm_send_button': 'पुष्टि करें और भेजें',
    'vault_files_not_initialized': 'इस डिवाइस पर Vault Files प्रारंभ नहीं किया गया है।',
    'invalid_vault_files_code': 'अमान्य Vault Files कोड।',
    'vault_files_corrupted': 'Vault Files डेटा दूषित है (कोड सही था, लेकिन वॉल्ट फ़ाइल स्वयं क्षतिग्रस्त है)।',
    'create_vault_files_code_title': 'VAULT FILES कोड बनाएं',
    'enter_vault_files_code_title': 'VAULT FILES कोड दर्ज करें',
    'vault_files_code_desc_create': 'यह कोड आपके ऐप अनलॉक कोड से अलग है। आपका ऐप कोड जानने वाला कोई भी व्यक्ति इस कोड के बिना आपकी तस्वीरें और दस्तावेज़ नहीं खोल पाएगा।',
    'vault_files_code_desc_enter': 'अपनी एन्क्रिप्टेड तस्वीरें और दस्तावेज़ देखने के लिए अपना Vault Files कोड दर्ज करें।',
    'set_vault_files_code_label': 'Vault Files कोड सेट करें',
    'vault_files_code_label': 'Vault Files कोड',
    'create_vault_button': 'वॉल्ट बनाएं',
    'imported_skipped_toast': '{imported} आयात किए गए, {skipped} छोड़े गए (प्रत्येक अधिकतम {mb}MB)।',
    'no_contacts_yet': 'अभी तक कोई संपर्क नहीं है।',
    'send_to_title': 'इसे भेजें...',
    'sent_toast': 'भेज दिया गया।',
    'failed_to_send_prefix': 'भेजना विफल',
    'received_from_prefix': 'से प्राप्त हुआ',
    'sent_to_prefix': 'को भेजा गया',
    'stored_locally_not_sent': 'स्थानीय रूप से संग्रहीत — अभी तक किसी को नहीं भेजा गया',
    'document_label': 'दस्तावेज़',
    'document_stored_encrypted_desc': 'यह दस्तावेज़ आपके Vault Files में एन्क्रिप्टेड रूप से संग्रहीत है ({kb} KB)। इसे फिर से फ़ोन में सहेजने या साझा करने के लिए एक्सपोर्ट का उपयोग करें।',
    'export_button': 'एक्सपोर्ट',
    'personal_files_empty': 'अभी तक कोई व्यक्तिगत फ़ाइल नहीं है।\nफ़ोटो लेने या दस्तावेज़ आयात करने के लिए + बटन का उपयोग करें।',
    'received_files_empty': 'अभी तक कुछ प्राप्त नहीं हुआ है।',
    'sent_files_empty': 'अभी तक कुछ भेजा नहीं गया है।',
    'tab_personal': 'व्यक्तिगत',
    'tab_received': 'प्राप्त',
    'tab_sent': 'भेजे गए',
    'copy_message': 'संदेश कॉपी करें',
    'destroy_message': 'संदेश नष्ट करें',
    'node_destruction_title': 'नोड विनाश',
    'destroy_message_confirm_body': 'क्या आप इस संदेश को दोनों डिवाइसों पर स्थायी रूप से नष्ट करना चाहते हैं?',
    'destroy_button': 'नष्ट करें',
    'failed_to_send_photo_prefix': 'फ़ोटो भेजने में विफल',
    'encrypted_photo_sent_message': '🖼️ एन्क्रिप्टेड फ़ोटो भेजी गई — Secure Vault Files में देखें',
    'photo_chat_preview': '🖼️ फ़ोटो',
    'just_now': 'अभी अभी',
    'failed_to_send_voice_prefix': 'वॉइस संदेश भेजने में विफल',
    'voice_message_chat_preview': '🎤 वॉइस संदेश',
    'voice_message_label': 'वॉइस संदेश',
    'no_secure_channel_error': 'भेजा नहीं जा सका: इस संपर्क के साथ अभी तक कोई सुरक्षित चैनल नहीं है ({error})। इसे हटाकर फिर से जोड़ने का प्रयास करें।',
    'block_id_title': 'ID ब्लॉक करें',
    'block_id_confirm_body': 'क्या आप इस ID को स्थायी रूप से ब्लॉक करना चाहते हैं?',
    'block_button': 'ब्लॉक करें',
    'keys_not_available': 'इस संपर्क के लिए कुंजियाँ उपलब्ध नहीं हैं।',
    'safety_number_title': 'सुरक्षा नंबर',
    'safety_number_desc': 'इस संपर्क को एक सुरक्षित कॉल करें और इस नंबर को ज़ोर से पढ़ें। यदि यह दोनों डिवाइसों पर मेल खाता है, तो कोई भी आपकी बातचीत को इंटरसेप्ट नहीं कर रहा है।',
    'verify_safety_number': 'सुरक्षा नंबर सत्यापित करें',
    'encrypted_p2p_channel': 'एन्क्रिप्टेड P2P चैनल',
    'destruct_1m': '1 मिनट',
    'destruct_5m': '5 मिनट',
    'destruct_1h': '1 घंटा',
    'destruct_24h': '24 घंटे',
    'message_not_decrypted': '[संदेश डिक्रिप्ट नहीं हुआ]',
    'call_status_connecting': 'कनेक्ट हो रहा है...',
    'call_status_exchanging_keys': 'एन्क्रिप्शन कुंजियों का आदान-प्रदान हो रहा है...',
    'call_status_ringing': 'घंटी बज रही है...',
    'call_status_connecting_encrypted': 'एन्क्रिप्टेड कॉल कनेक्ट हो रही है...',
    'call_status_incoming_encrypted': 'आने वाली एन्क्रिप्टेड कॉल...',
    'call_status_connected_prefix': 'कनेक्ट हो गया',
    'call_status_connected_encrypted': 'कनेक्ट और एन्क्रिप्टेड',
    'call_status_reconnecting': 'पुनः कनेक्ट हो रहा है...',
    'call_contact_unavailable': 'संपर्क अनुपलब्ध है या ऑफ़लाइन है।',
    'missed_secure_call': 'छूटी हुई सुरक्षित कॉल',
    'missed_call_notification_title': 'छूटी हुई कॉल',
    'setup_code_too_weak': 'डिक्रिप्शन कुंजी बहुत कमज़ोर है: कम से कम 10 अक्षरों का उपयोग करें और दोहराए जाने वाले या क्रमिक पैटर्न से बचें।',
    'vault_init_failed_prefix': 'वॉल्ट प्रारंभ करने में विफल',
    'create_vault_title': 'अपना एन्क्रिप्टेड वॉल्ट बनाएं',
    'create_vault_subtitle': 'अपनी P2P क्रिप्टोग्राफिक पहचान बनाने के लिए\nअपनी मास्टर कुंजी सेट करें',
    'set_decryption_key_label': 'डिक्रिप्शन कुंजी सेट करें',
    'strength_too_weak': 'बहुत कमज़ोर',
    'strength_weak': 'कमज़ोर',
    'strength_medium': 'मध्यम',
    'strength_strong': 'मजबूत',
    'strength_very_strong': 'बहुत मजबूत',
    'initialize_vault_button': 'वॉल्ट प्रारंभ करें',
    'footer_privacy_text': 'सैन्य-ग्रेड ज़ीरो-नॉलेज एन्क्रिप्शन के साथ इंजीनियर किया गया।\nसभी संचार सख्ती से पीयर-टू-पीयर (P2P) पर काम करते हैं।\nसुरक्षित एंटी-ट्रेस मेमोरी सैनिटाइज़ेशन का उपयोग करके\nसंदेश 24 घंटे बाद स्वचालित रूप से नष्ट हो जाते हैं।\nशून्य निशान, शून्य लॉग, पूर्ण गोपनीयता।',
    'vault_not_initialized_device': 'इस डिवाइस पर वॉल्ट प्रारंभ नहीं किया गया है।',
    'invalid_decryption_key': 'अमान्य डिक्रिप्शन कुंजी।',
    'vault_data_corrupted': 'वॉल्ट डेटा दूषित है (कुंजी सही थी, लेकिन वॉल्ट फ़ाइल स्वयं क्षतिग्रस्त है)।',
    'decrypt_padlock_title': 'अपना PADLOCK डिक्रिप्ट करें',
    'login_subtitle': 'सैन्य-ग्रेड ज़ीरो-नॉलेज एन्क्रिप्शन के साथ इंजीनियर किया गया',
    'enter_decryption_key_label': 'डिक्रिप्शन कुंजी दर्ज करें',
    'access_vault_button': 'वॉल्ट तक पहुंचें',
  },
  'NL': {
    'chats': 'Chats',
    'contacts': 'Contacten',
    'settings': 'Instellingen',
    'profile': 'Profiel',
    'search_hint': 'Zoeken in beveiligde database...',
    'autodestruct': 'Zelfvernietiging over',
    'bio_label': 'Bio',
    'bio_text': 'P2P-versleuteld knooppunt / Militaire beveiliging',
    'username_label': 'Gebruikersnaam',
    'copy_toast': 'ID gekopieerd naar klembord!',
    'qr_title': 'Privacy QR-code',
    'qr_desc': 'Scan deze code om een beveiligde P2P-verbinding tot stand te brengen.',
    'call': 'Beveiligde oproep',
    'new_chat': 'Nieuw beveiligd kanaal',
    'delete_chat': 'Gesprek wissen',
    'block_peer': 'Hex-ID blokkeren',
    'send_hint': 'Versleuteld bericht typen...',
    'custom_sound': 'Exclusief Padlock-geluid (Vast)',
    'silent_mode': 'Stille modus',
    'notifications': 'Meldingen',
    'sounds_desc': 'Het systeem gebruikt exclusieve versleutelde tonen.',
    'app_lock': 'Toegangscode vergrendeling',
    'screen_security': 'Schermafbeeldingen blokkeren',
    'clear_keys': 'Versleutelingssleutels wissen',
    'keys_purged': 'Alle sessiesleutels zijn veilig vernietigd.',
    'offline_contacts': 'Actieve P2P-contacten',
    'empty_contacts': 'Geen contacten gevonden in lokaal netwerk.',
    'language': 'Taal',
    'search_contact_hint': 'Contact zoeken...',
    'encrypted_p2p_contact': 'Versleuteld P2P-contact',
    'encrypted_p2p_message_preview': '[Versleuteld P2P-bericht]',
    'delete_chat_confirm_title': 'Gesprek verwijderen',
    'delete_chat_confirm_body': 'Wil je dit gesprek permanent verwijderen?',
    'cancel_button': 'Annuleren',
    'delete_button': 'Verwijderen',
    'settings_header': 'INSTELLINGEN',
    'section_core_security': 'Kernbeveiligingsprotocollen',
    'info_encryption_title': 'Militaire Versleuteling',
    'info_encryption_desc': 'AES-256-GCM- en Curve25519-standaard.',
    'info_p2p_title': 'Echte Peer-to-Peer',
    'info_p2p_desc': 'Directe spraak en gegevens. Geen serverroutering.',
    'info_autodestruct_title': 'Forensische Zelfvernietiging',
    'info_autodestruct_desc': 'Alle berichten worden binnen maximaal 24 uur vernietigd.',
    'info_screenshot_title': 'Schermafbeeldingbescherming',
    'info_screenshot_desc': 'Schermopname wordt app-breed geblokkeerd om ongeautoriseerde datalekken te voorkomen.',
    'info_timeout_title': 'Veilige Time-out',
    'info_timeout_desc': 'De app sluit voor uw veiligheid automatisch na 15 minuten gebruik. Opnieuw inloggen is vereist om verder te gaan. Actieve oproepen negeren deze regel om de verbinding te behouden.',
    'section_premium': 'Padlock Premium',
    'secure_crypto_vault_title': 'Secure Crypto Vault',
    'crypto_vault_desc': 'Opslag met maximale beveiliging voor uw digitale bezittingen.',
    'section_help_center': 'Helpcentrum / Hoe te gebruiken',
    'help_vault_files_q': 'Hoe gebruik ik Secure Vault Files?',
    'help_vault_files_a': 'Om toegang te krijgen tot deze sectie, moet u een speciale versleutelde sleutel aanmaken. Telkens wanneer u de kluis opent, wordt u om deze sleutel gevraagd om in te loggen, net als bij de beveiligingslogin van de app.\n\n• Alle foto\'s die rechtstreeks in Padlock zijn gemaakt, worden hier automatisch opgeslagen.\n• Documenten en foto\'s die contacten naar uw ID sturen, worden rechtstreeks naar deze kluis geleid in plaats van naar normale chats. U ontvangt een melding dat media is verzonden, en u moet deze in de kluis bekijken.\n• Bestanden blijven 100% versleuteld en veilig totdat ze handmatig worden verwijderd, geëxporteerd of opnieuw verzonden.',
    'help_add_contact_q': 'Hoe voeg ik een contact toe?',
    'help_add_contact_a': 'Ga naar het tabblad "Contacten", tik op de blauwe (+) knop en plak een privacy-ID of gebruik de groene QR-scanner.',
    'help_share_id_q': 'Hoe deel ik mijn ID?',
    'help_share_id_a': 'Ga naar het tabblad "Profiel". Tik op "Copy ID" om deze veilig ergens te plakken, of op "QR Code" zodat iemand uw scherm kan scannen.',
    'help_rename_contact_q': 'Hoe hernoem ik een contact?',
    'help_rename_contact_a': 'Tik in het tabblad "Contacten" op het bewerkingspictogram (potlood) naast een contact om de weergavenaam te wijzigen.',
    'help_delete_contact_q': 'Hoe verwijder ik een contact?',
    'help_delete_contact_a': 'Houd in het tabblad "Contacten" een contact ingedrukt. Dit verwijdert het permanent en vernietigt de gedeelde versleutelingssleutels.',
    'help_wipe_chat_q': 'Hoe wis ik een gesprek?',
    'help_wipe_chat_a': 'Tik in een actieve chat op het menu (drie stippen) rechtsboven en selecteer "Gesprek Wissen" om alle berichten op beide apparaten te vernietigen.',
    'section_app_preferences': 'App-voorkeuren',
    'app_language_title': 'App-taal',
    'current_lang_prefix': 'Huidig',
    'silent_mode_desc': 'Dempt alle meldingen en beltonen.',
    'section_panic_room': 'Paniekkamer',
    'nuke_vault_title': 'KLUIS VERNIETIGEN: ALLES WISSEN EN VERNIETIGEN',
    'nuke_vault_desc': 'Deze actie vernietigt permanent uw privacy-ID, cryptofondsen en alle chats. Het wist alles en brengt u terug naar het activatiescherm.',
    'critical_warning_title': 'KRITIEKE WAARSCHUWING',
    'nuke_confirm_body': 'Weet u zeker dat u de kluis wilt VERNIETIGEN?\n\n⚠️ HAAL AL UW CRYPTOFONDSEN OP EN SLA UW BESTANDEN OP VOORDAT U DOORGAAT.\n\nDeze actie is onomkeerbaar. De applicatie wordt teruggezet naar fabrieksinstellingen.',
    'nuke_everything_button': 'ALLES VERNIETIGEN',
    'got_it_button': 'Begrepen',
    'edit_name_title': 'Naam Bewerken',
    'save_button': 'Opslaan',
    'qr_code_button': 'QR-code',
    'copy_id_button': 'ID Kopiëren',
    'secure_crypto_vault_short': 'Secure\nCrypto Vault',
    'secure_vault_files_short': 'Secure\nVault Files',
    'privacy_id_label': 'Privacy-ID',
    'profile_bio_paragraph': 'Ontworpen met militaire Zero-Knowledge-versleuteling.\nAlle communicatie werkt strikt Peer-to-Peer (P2P).\nBerichten vernietigen zichzelf automatisch na 24 uur\nmet behulp van veilige anti-tracering geheugensanering.\nGeen spoor, geen logboeken, volledige privacy.',
    'close_button': 'Sluiten',
    'crypto_code_too_weak': 'Code is te zwak: gebruik minstens 10 tekens en vermijd herhalende of opeenvolgende patronen.',
    'invalid_recovery_phrase': 'Ongeldige herstelzin - controleer de woorden en probeer het opnieuw.',
    'crypto_vault_not_initialized': 'Crypto Vault is niet geïnitialiseerd op dit apparaat.',
    'invalid_crypto_vault_code': 'Ongeldige Crypto Vault-code.',
    'crypto_vault_corrupted': 'Crypto Vault-gegevens zijn beschadigd (code was correct, maar het kluisbestand zelf is beschadigd).',
    'create_crypto_vault_code_title': 'MAAK CRYPTO VAULT-CODE',
    'enter_crypto_vault_code_title': 'VOER CRYPTO VAULT-CODE IN',
    'crypto_code_desc_create': 'Deze code is anders dan die van je app en Vault Files. Het beschermt een volledig nieuwe, non-custodiale wallet die alleen jij beheert.',
    'crypto_code_desc_enter': 'Voer je Crypto Vault-code in om toegang te krijgen tot je wallet.',
    'create_new_wallet_instead': '← Maak in plaats daarvan een nieuwe wallet',
    'already_have_recovery_phrase': 'Ik heb al een herstelzin (telefoon kwijt / opnieuw geïnstalleerd)',
    'recovery_phrase_label': 'Je herstelzin van 12 woorden',
    'recovery_phrase_hint': 'woord1 woord2 woord3 ...',
    'set_crypto_vault_code_label': 'Stel Crypto Vault-code in (voor dit apparaat)',
    'crypto_vault_code_label': 'Crypto Vault-code',
    'restore_wallet_button': 'Wallet herstellen',
    'create_wallet_button': 'Wallet aanmaken',
    'unlock_button': 'Ontgrendelen',
    'recovery_phrase_title': 'Je herstelzin',
    'recovery_phrase_warning': '⚠️ Schrijf deze 12 woorden in volgorde op papier en bewaar ze ergens veilig en offline. Iedereen met deze woorden kan je geld stelen. Padlock slaat deze zin nergens op en kan hem niet voor je herstellen.',
    'recovery_phrase_confirm_checkbox': 'Ik heb deze woorden opgeschreven en veilig offline bewaard.',
    'continue_button': 'Doorgaan',
    'loading_text': 'Laden...',
    'could_not_load_balance': 'Saldo kon niet worden geladen',
    'receive_dialog_title': 'Ontvangen',
    'receive_address_warning': 'Het scannen of delen van deze code onthult alleen je walletadres - nooit je herstelzin.',
    'address_copied_toast': 'Adres gekopieerd.',
    'copy_button': 'Kopiëren',
    'testnet_warning': '⚠️ Testnet (Polygon Amoy) - dit is geen echt geld.',
    'balances_label': 'Saldi',
    'receive_button': 'Ontvangen',
    'send_button': 'Verzenden',
    'camera_permission_denied': 'Camerarechten geweigerd. Schakel dit in bij Telefooninstellingen > Apps > Padlock > Rechten.',
    'scan_wallet_address_title': 'Scan walletadres',
    'invalid_wallet_address': 'Ongeldig walletadres.',
    'enter_valid_amount': 'Voer een geldig bedrag in.',
    'price_not_loaded': 'Prijs nog niet geladen - probeer het over een moment opnieuw.',
    'transaction_sent_title': 'Transactie verzonden',
    'done_button': 'Klaar',
    'send_failed_prefix': 'Verzenden mislukt',
    'send_title': 'Verzenden',
    'recipient_address_label': 'Walletadres van ontvanger',
    'coin_label': 'Munt',
    'amount_in_label': 'Bedrag in:',
    'amount_usd_label': 'Bedrag (USD)',
    'amount_label_prefix': 'Bedrag',
    'loading_price': 'Prijs laden...',
    'price_label_prefix': 'Prijs',
    'confirm_send_button': 'Bevestigen en verzenden',
    'vault_files_not_initialized': 'Vault Files is niet geïnitialiseerd op dit apparaat.',
    'invalid_vault_files_code': 'Ongeldige Vault Files-code.',
    'vault_files_corrupted': 'Vault Files-gegevens zijn beschadigd (code was correct, maar het kluisbestand zelf is beschadigd).',
    'create_vault_files_code_title': 'MAAK VAULT FILES-CODE',
    'enter_vault_files_code_title': 'VOER VAULT FILES-CODE IN',
    'vault_files_code_desc_create': 'Deze code is anders dan je app-ontgrendelingscode. Iemand die je app-code kent, kan je foto\'s en documenten NIET openen zonder deze code.',
    'vault_files_code_desc_enter': 'Voer je Vault Files-code in om je versleutelde foto\'s en documenten te bekijken.',
    'set_vault_files_code_label': 'Stel Vault Files-code in',
    'vault_files_code_label': 'Vault Files-code',
    'create_vault_button': 'KLUIS AANMAKEN',
    'imported_skipped_toast': '{imported} geïmporteerd, {skipped} overgeslagen (max {mb}MB per stuk).',
    'no_contacts_yet': 'Nog geen contacten.',
    'send_to_title': 'Verzenden naar...',
    'sent_toast': 'Verzonden.',
    'failed_to_send_prefix': 'Verzenden mislukt',
    'received_from_prefix': 'Ontvangen van',
    'sent_to_prefix': 'Verzonden naar',
    'stored_locally_not_sent': 'Lokaal opgeslagen — nog naar niemand verzonden',
    'document_label': 'Document',
    'document_stored_encrypted_desc': 'Dit document is versleuteld opgeslagen in je Vault Files ({kb} KB). Gebruik Exporteren om het weer op je telefoon op te slaan of te delen.',
    'export_button': 'Exporteren',
    'personal_files_empty': 'Nog geen persoonlijke bestanden.\nGebruik de +-knop om een foto te maken of een document te importeren.',
    'received_files_empty': 'Nog niets ontvangen.',
    'sent_files_empty': 'Nog niets verzonden.',
    'tab_personal': 'Persoonlijk',
    'tab_received': 'Ontvangen',
    'tab_sent': 'Verzonden',
    'copy_message': 'Bericht Kopiëren',
    'destroy_message': 'Bericht Vernietigen',
    'node_destruction_title': 'Knooppuntvernietiging',
    'destroy_message_confirm_body': 'Wil je dit bericht permanent vernietigen op beide apparaten?',
    'destroy_button': 'Vernietigen',
    'failed_to_send_photo_prefix': 'Foto verzenden mislukt',
    'encrypted_photo_sent_message': '🖼️ Versleutelde foto verzonden — bekijk in Secure Vault Files',
    'photo_chat_preview': '🖼️ Foto',
    'just_now': 'Zojuist',
    'failed_to_send_voice_prefix': 'Spraakbericht verzenden mislukt',
    'voice_message_chat_preview': '🎤 Spraakbericht',
    'voice_message_label': 'Spraakbericht',
    'no_secure_channel_error': 'Kan niet verzenden: nog geen beveiligd kanaal met dit contact ({error}). Probeer het te verwijderen en opnieuw toe te voegen.',
    'block_id_title': 'ID Blokkeren',
    'block_id_confirm_body': 'Wil je deze ID permanent blokkeren?',
    'block_button': 'Blokkeren',
    'keys_not_available': 'Sleutels niet beschikbaar voor dit contact.',
    'safety_number_title': 'Veiligheidsnummer',
    'safety_number_desc': 'Bel dit contact veilig op en lees dit nummer hardop voor. Komt het op beide apparaten overeen, dan onderschept niemand je gesprek.',
    'verify_safety_number': 'Veiligheidsnummer Verifiëren',
    'encrypted_p2p_channel': 'Versleuteld P2P-kanaal',
    'destruct_1m': '1 Minuut',
    'destruct_5m': '5 Minuten',
    'destruct_1h': '1 Uur',
    'destruct_24h': '24 Uur',
    'message_not_decrypted': '[Bericht niet ontsleuteld]',
    'call_status_connecting': 'Verbinden...',
    'call_status_exchanging_keys': 'Versleutelingssleutels uitwisselen...',
    'call_status_ringing': 'Bellen...',
    'call_status_connecting_encrypted': 'Versleutelde oproep verbinden...',
    'call_status_incoming_encrypted': 'Inkomende versleutelde oproep...',
    'call_status_connected_prefix': 'Verbonden',
    'call_status_connected_encrypted': 'Verbonden en versleuteld',
    'call_status_reconnecting': 'Opnieuw verbinden...',
    'call_contact_unavailable': 'Contact niet beschikbaar of offline.',
    'missed_secure_call': 'Gemiste Beveiligde Oproep',
    'missed_call_notification_title': 'Gemiste Oproep',
    'setup_code_too_weak': 'Decoderingssleutel is te zwak: gebruik minstens 10 tekens en vermijd herhalende of opeenvolgende patronen.',
    'vault_init_failed_prefix': 'Initialisatie van kluis mislukt',
    'create_vault_title': 'MAAK JE VERSLEUTELDE KLUIS',
    'create_vault_subtitle': 'Stel je hoofdsleutel in om je\nP2P-cryptografische identiteit te genereren',
    'set_decryption_key_label': 'Decoderingssleutel Instellen',
    'strength_too_weak': 'Te zwak',
    'strength_weak': 'Zwak',
    'strength_medium': 'Gemiddeld',
    'strength_strong': 'Sterk',
    'strength_very_strong': 'Zeer sterk',
    'initialize_vault_button': 'KLUIS INITIALISEREN',
    'footer_privacy_text': 'Ontworpen met Zero-Knowledge-versleuteling van militaire kwaliteit.\nAlle communicatie werkt strikt Peer-to-Peer (P2P).\nBerichten vernietigen zichzelf automatisch na 24 uur\nmet behulp van veilige anti-spoor geheugensanering.\nGeen sporen, geen logs, volledige privacy.',
    'vault_not_initialized_device': 'Kluis niet geïnitialiseerd op dit apparaat.',
    'invalid_decryption_key': 'Ongeldige decoderingssleutel.',
    'vault_data_corrupted': 'Kluisgegevens zijn beschadigd (sleutel was correct, maar het kluisbestand zelf is beschadigd).',
    'decrypt_padlock_title': 'ONTGRENDEL JE PADLOCK',
    'login_subtitle': 'ONTWORPEN MET ZERO-KNOWLEDGE-VERSLEUTELING\nVAN MILITAIRE KWALITEIT',
    'enter_decryption_key_label': 'Decoderingssleutel Invoeren',
    'access_vault_button': 'KLUIS OPENEN',
  },
  'PL': {
    'chats': 'Czaty',
    'contacts': 'Kontakty',
    'settings': 'Ustawienia',
    'profile': 'Profil',
    'search_hint': 'Przeszukaj bezpieczną bazę danych...',
    'autodestruct': 'Samozniszczenie za',
    'bio_label': 'Bio',
    'bio_text': 'Węzeł szyfrowany P2P / Bezpieczeństwo wojskowe',
    'username_label': 'Nazwa użytkownika',
    'copy_toast': 'ID skopiowane do schowka!',
    'qr_title': 'Kod QR prywatności',
    'qr_desc': 'Zeskanuj ten kod, aby nawiązać bezpieczne połączenie P2P.',
    'call': 'Bezpieczne połączenie',
    'new_chat': 'Nowy bezpieczny kanał',
    'delete_chat': 'Usuń rozmowę',
    'block_peer': 'Zablokuj Hex ID',
    'send_hint': 'Napisz zaszyfrowaną wiadomość...',
    'custom_sound': 'Ekskluzywny dźwięk Padlock (Stały)',
    'silent_mode': 'Tryb cichy',
    'notifications': 'Powiadomienia',
    'sounds_desc': 'System używa ekskluzywnych zaszyfrowanych dźwięków.',
    'app_lock': 'Blokada kodem',
    'screen_security': 'Blokuj zrzuty ekranu',
    'clear_keys': 'Wyczyść klucze szyfrowania',
    'keys_purged': 'Wszystkie klucze sesji zostały bezpiecznie zniszczone.',
    'offline_contacts': 'Aktywne kontakty P2P',
    'empty_contacts': 'Nie znaleziono kontaktów w sieci lokalnej.',
    'language': 'Język',
    'search_contact_hint': 'Szukaj kontaktu...',
    'encrypted_p2p_contact': 'Zaszyfrowany kontakt P2P',
    'encrypted_p2p_message_preview': '[Zaszyfrowana wiadomość P2P]',
    'delete_chat_confirm_title': 'Usuń rozmowę',
    'delete_chat_confirm_body': 'Czy chcesz trwale usunąć tę rozmowę?',
    'cancel_button': 'Anuluj',
    'delete_button': 'Usuń',
    'settings_header': 'USTAWIENIA',
    'section_core_security': 'Główne Protokoły Bezpieczeństwa',
    'info_encryption_title': 'Szyfrowanie Wojskowej Klasy',
    'info_encryption_desc': 'Standard AES-256-GCM i Curve25519.',
    'info_p2p_title': 'Prawdziwe Peer-to-Peer',
    'info_p2p_desc': 'Bezpośredni głos i dane. Zero routingu przez serwer.',
    'info_autodestruct_title': 'Kryminalistyczne Auto-Niszczenie',
    'info_autodestruct_desc': 'Wszystkie wiadomości są niszczone w ciągu maksymalnie 24 godzin.',
    'info_screenshot_title': 'Ochrona Przed Zrzutami Ekranu',
    'info_screenshot_desc': 'Przechwytywanie ekranu jest globalnie zablokowane w całej aplikacji, aby zapobiec nieautoryzowanym wyciekom danych.',
    'info_timeout_title': 'Bezpieczne Automatyczne Wylogowanie',
    'info_timeout_desc': 'Aplikacja zamyka się automatycznie po 15 minutach użytkowania dla Twojego bezpieczeństwa. Aby kontynuować, wymagane jest ponowne zalogowanie. Aktywne połączenia pomijają tę zasadę, aby utrzymać połączenie.',
    'section_premium': 'Padlock Premium',
    'secure_crypto_vault_title': 'Secure Crypto Vault',
    'crypto_vault_desc': 'Przechowywanie o maksymalnym bezpieczeństwie dla Twoich cyfrowych aktywów.',
    'section_help_center': 'Centrum Pomocy / Jak Korzystać',
    'help_vault_files_q': 'Jak korzystać z Secure Vault Files?',
    'help_vault_files_a': 'Aby uzyskać dostęp do tej sekcji, musisz utworzyć dedykowany klucz szyfrujący. Za każdym razem, gdy otworzysz skarbiec, zostaniesz poproszony o ten klucz do zalogowania, podobnie jak przy logowaniu zabezpieczającym aplikacji.\n\n• Wszystkie zdjęcia zrobione bezpośrednio w Padlock są tutaj automatycznie zapisywane.\n• Dokumenty i zdjęcia wysyłane przez kontakty na Twój ID są kierowane bezpośrednio do tego skarbca zamiast do zwykłych czatów. Otrzymasz powiadomienie, że wysłano multimedia, i musisz uzyskać do nich dostęp wewnątrz skarbca, aby je zobaczyć.\n• Pliki pozostają w 100% zaszyfrowane i bezpieczne, dopóki nie zostaną ręcznie usunięte, wyeksportowane lub wysłane ponownie.',
    'help_add_contact_q': 'Jak dodać kontakt?',
    'help_add_contact_a': 'Przejdź do zakładki "Kontakty", dotknij niebieskiego przycisku (+) i wklej ID prywatności lub użyj zielonego skanera QR.',
    'help_share_id_q': 'Jak udostępnić mój ID?',
    'help_share_id_a': 'Przejdź do zakładki "Profil". Dotknij "Copy ID", aby bezpiecznie wkleić go gdziekolwiek, lub "QR Code", aby ktoś zeskanował Twój ekran.',
    'help_rename_contact_q': 'Jak zmienić nazwę kontaktu?',
    'help_rename_contact_a': 'W zakładce "Kontakty" dotknij ikony edycji (ołówek) obok dowolnego kontaktu, aby zmienić jego wyświetlaną nazwę.',
    'help_delete_contact_q': 'Jak usunąć kontakt?',
    'help_delete_contact_a': 'W zakładce "Kontakty" naciśnij i przytrzymaj dowolny kontakt. Spowoduje to jego trwałe usunięcie i zniszczenie wspólnych kluczy szyfrujących.',
    'help_wipe_chat_q': 'Jak usunąć rozmowę?',
    'help_wipe_chat_a': 'W dowolnym aktywnym czacie dotknij menu (trzy kropki) w prawym górnym rogu i wybierz "Usuń rozmowę", aby zniszczyć wszystkie wiadomości na obu urządzeniach.',
    'section_app_preferences': 'Preferencje Aplikacji',
    'app_language_title': 'Język Aplikacji',
    'current_lang_prefix': 'Obecny',
    'silent_mode_desc': 'Wycisza wszystkie powiadomienia i dzwonki połączeń.',
    'section_panic_room': 'Pokój Paniki',
    'nuke_vault_title': 'ZNISZCZ SKARBIEC: WYCZYŚĆ I ZNISZCZ WSZYSTKO',
    'nuke_vault_desc': 'Ta akcja trwale zniszczy Twój ID prywatności, środki kryptowalutowe i wszystkie czaty. Czyści wszystko i przenosi Cię z powrotem do ekranu aktywacji.',
    'critical_warning_title': 'KRYTYCZNE OSTRZEŻENIE',
    'nuke_confirm_body': 'Czy na pewno chcesz ZNISZCZYĆ skarbiec?\n\n⚠️ WYPŁAĆ WSZYSTKIE ŚRODKI KRYPTOWALUTOWE I ZAPISZ SWOJE PLIKI PRZED KONTYNUOWANIEM.\n\nTa akcja jest nieodwracalna. Aplikacja zostanie przywrócona do stanu fabrycznego.',
    'nuke_everything_button': 'ZNISZCZ WSZYSTKO',
    'got_it_button': 'Rozumiem',
    'edit_name_title': 'Edytuj Imię',
    'save_button': 'Zapisz',
    'qr_code_button': 'Kod QR',
    'copy_id_button': 'Kopiuj ID',
    'secure_crypto_vault_short': 'Secure\nCrypto Vault',
    'secure_vault_files_short': 'Secure\nVault Files',
    'privacy_id_label': 'ID Prywatności',
    'profile_bio_paragraph': 'Zaprojektowano z szyfrowaniem Zero-Knowledge wojskowej klasy.\nWszystkie komunikacje działają ściśle w trybie Peer-to-Peer (P2P).\nWiadomości automatycznie samoniszczą się po 24 godzinach\nprzy użyciu bezpiecznego czyszczenia pamięci anty-śledzenia.\nZero śladu, zero logów, pełna prywatność.',
    'close_button': 'Zamknij',
    'crypto_code_too_weak': 'Kod jest za słaby: użyj co najmniej 10 znaków i unikaj powtarzających się lub sekwencyjnych wzorców.',
    'invalid_recovery_phrase': 'Nieprawidłowa fraza odzyskiwania - sprawdź słowa i spróbuj ponownie.',
    'crypto_vault_not_initialized': 'Crypto Vault nie został zainicjowany na tym urządzeniu.',
    'invalid_crypto_vault_code': 'Nieprawidłowy kod Crypto Vault.',
    'crypto_vault_corrupted': 'Dane Crypto Vault są uszkodzone (kod był poprawny, ale sam plik skarbca jest uszkodzony).',
    'create_crypto_vault_code_title': 'UTWÓRZ KOD CRYPTO VAULT',
    'enter_crypto_vault_code_title': 'WPROWADŹ KOD CRYPTO VAULT',
    'crypto_code_desc_create': 'Ten kod różni się od kodu aplikacji i Vault Files. Chroni zupełnie nowy, niekustodialny portfel, który kontrolujesz tylko Ty.',
    'crypto_code_desc_enter': 'Wprowadź swój kod Crypto Vault, aby uzyskać dostęp do portfela.',
    'create_new_wallet_instead': '← Utwórz zamiast tego nowy portfel',
    'already_have_recovery_phrase': 'Mam już frazę odzyskiwania (zgubiony telefon / ponowna instalacja)',
    'recovery_phrase_label': 'Twoja 12-wyrazowa fraza odzyskiwania',
    'recovery_phrase_hint': 'słowo1 słowo2 słowo3 ...',
    'set_crypto_vault_code_label': 'Ustaw kod Crypto Vault (dla tego urządzenia)',
    'crypto_vault_code_label': 'Kod Crypto Vault',
    'restore_wallet_button': 'Przywróć portfel',
    'create_wallet_button': 'Utwórz portfel',
    'unlock_button': 'Odblokuj',
    'recovery_phrase_title': 'Twoja fraza odzyskiwania',
    'recovery_phrase_warning': '⚠️ Zapisz te 12 słów w kolejności na papierze i przechowuj je w bezpiecznym miejscu offline. Każdy, kto zna te słowa, może ukraść Twoje środki. Padlock nigdzie nie przechowuje tej frazy i nie może jej dla Ciebie odzyskać.',
    'recovery_phrase_confirm_checkbox': 'Zapisałem te słowa i przechowuję je bezpiecznie offline.',
    'continue_button': 'Kontynuuj',
    'loading_text': 'Ładowanie...',
    'could_not_load_balance': 'Nie udało się załadować salda',
    'receive_dialog_title': 'Odbierz',
    'receive_address_warning': 'Skanowanie lub udostępnianie tego kodu ujawnia tylko adres Twojego portfela - nigdy Twoją frazę odzyskiwania.',
    'address_copied_toast': 'Adres skopiowany.',
    'copy_button': 'Kopiuj',
    'testnet_warning': '⚠️ Testnet (Polygon Amoy) - to nie są prawdziwe środki.',
    'balances_label': 'Salda',
    'receive_button': 'Odbierz',
    'send_button': 'Wyślij',
    'camera_permission_denied': 'Odmówiono dostępu do kamery. Włącz go w Ustawienia telefonu > Aplikacje > Padlock > Uprawnienia.',
    'scan_wallet_address_title': 'Skanuj adres portfela',
    'invalid_wallet_address': 'Nieprawidłowy adres portfela.',
    'enter_valid_amount': 'Wprowadź prawidłową kwotę.',
    'price_not_loaded': 'Cena nie została jeszcze załadowana - spróbuj ponownie za chwilę.',
    'transaction_sent_title': 'Transakcja wysłana',
    'done_button': 'Gotowe',
    'send_failed_prefix': 'Wysyłanie nie powiodło się',
    'send_title': 'Wyślij',
    'recipient_address_label': 'Adres portfela odbiorcy',
    'coin_label': 'Moneta',
    'amount_in_label': 'Kwota w:',
    'amount_usd_label': 'Kwota (USD)',
    'amount_label_prefix': 'Kwota',
    'loading_price': 'Ładowanie ceny...',
    'price_label_prefix': 'Cena',
    'confirm_send_button': 'Potwierdź i wyślij',
    'vault_files_not_initialized': 'Vault Files nie został zainicjowany na tym urządzeniu.',
    'invalid_vault_files_code': 'Nieprawidłowy kod Vault Files.',
    'vault_files_corrupted': 'Dane Vault Files są uszkodzone (kod był poprawny, ale sam plik skarbca jest uszkodzony).',
    'create_vault_files_code_title': 'UTWÓRZ KOD VAULT FILES',
    'enter_vault_files_code_title': 'WPROWADŹ KOD VAULT FILES',
    'vault_files_code_desc_create': 'Ten kod różni się od kodu odblokowania aplikacji. Osoba znająca kod aplikacji NIE będzie mogła otworzyć Twoich zdjęć i dokumentów bez tego kodu.',
    'vault_files_code_desc_enter': 'Wprowadź kod Vault Files, aby wyświetlić zaszyfrowane zdjęcia i dokumenty.',
    'set_vault_files_code_label': 'Ustaw kod Vault Files',
    'vault_files_code_label': 'Kod Vault Files',
    'create_vault_button': 'UTWÓRZ SKARBIEC',
    'imported_skipped_toast': 'Zaimportowano {imported}, pominięto {skipped} (maks. {mb}MB każdy).',
    'no_contacts_yet': 'Brak kontaktów.',
    'send_to_title': 'Wyślij do...',
    'sent_toast': 'Wysłano.',
    'failed_to_send_prefix': 'Wysyłanie nie powiodło się',
    'received_from_prefix': 'Otrzymano od',
    'sent_to_prefix': 'Wysłano do',
    'stored_locally_not_sent': 'Zapisano lokalnie — jeszcze nikomu nie wysłano',
    'document_label': 'Dokument',
    'document_stored_encrypted_desc': 'Ten dokument jest przechowywany zaszyfrowany w Vault Files ({kb} KB). Użyj Eksportuj, aby zapisać go z powrotem na telefonie lub udostępnić.',
    'export_button': 'Eksportuj',
    'personal_files_empty': 'Brak plików osobistych.\nUżyj przycisku +, aby zrobić zdjęcie lub zaimportować dokument.',
    'received_files_empty': 'Nic jeszcze nie otrzymano.',
    'sent_files_empty': 'Nic jeszcze nie wysłano.',
    'tab_personal': 'Osobiste',
    'tab_received': 'Otrzymane',
    'tab_sent': 'Wysłane',
    'copy_message': 'Kopiuj Wiadomość',
    'destroy_message': 'Zniszcz Wiadomość',
    'node_destruction_title': 'Zniszczenie Węzła',
    'destroy_message_confirm_body': 'Czy chcesz trwale zniszczyć tę wiadomość na obu urządzeniach?',
    'destroy_button': 'Zniszcz',
    'failed_to_send_photo_prefix': 'Nie udało się wysłać zdjęcia',
    'encrypted_photo_sent_message': '🖼️ Wysłano zaszyfrowane zdjęcie — zobacz w Secure Vault Files',
    'photo_chat_preview': '🖼️ Zdjęcie',
    'just_now': 'Przed chwilą',
    'failed_to_send_voice_prefix': 'Nie udało się wysłać wiadomości głosowej',
    'voice_message_chat_preview': '🎤 Wiadomość głosowa',
    'voice_message_label': 'Wiadomość głosowa',
    'no_secure_channel_error': 'Nie można wysłać: nie ma jeszcze bezpiecznego kanału z tym kontaktem ({error}). Spróbuj go usunąć i dodać ponownie.',
    'block_id_title': 'Zablokuj ID',
    'block_id_confirm_body': 'Czy chcesz trwale zablokować to ID?',
    'block_button': 'Zablokuj',
    'keys_not_available': 'Klucze niedostępne dla tego kontaktu.',
    'safety_number_title': 'Numer Bezpieczeństwa',
    'safety_number_desc': 'Zadzwoń bezpiecznie do tego kontaktu i przeczytaj ten numer na głos. Jeśli zgadza się na obu urządzeniach, nikt nie przechwytuje Twojej rozmowy.',
    'verify_safety_number': 'Zweryfikuj Numer Bezpieczeństwa',
    'encrypted_p2p_channel': 'Zaszyfrowany Kanał P2P',
    'destruct_1m': '1 Minuta',
    'destruct_5m': '5 Minut',
    'destruct_1h': '1 Godzina',
    'destruct_24h': '24 Godziny',
    'message_not_decrypted': '[Wiadomość nieodszyfrowana]',
    'call_status_connecting': 'Łączenie...',
    'call_status_exchanging_keys': 'Wymiana kluczy szyfrowania...',
    'call_status_ringing': 'Dzwonienie...',
    'call_status_connecting_encrypted': 'Łączenie szyfrowanego połączenia...',
    'call_status_incoming_encrypted': 'Nadchodzące szyfrowane połączenie...',
    'call_status_connected_prefix': 'Połączono',
    'call_status_connected_encrypted': 'Połączono i zaszyfrowano',
    'call_status_reconnecting': 'Ponowne łączenie...',
    'call_contact_unavailable': 'Kontakt niedostępny lub offline.',
    'missed_secure_call': 'Nieodebrane Bezpieczne Połączenie',
    'missed_call_notification_title': 'Nieodebrane Połączenie',
    'setup_code_too_weak': 'Klucz deszyfrowania jest za słaby: użyj co najmniej 10 znaków i unikaj powtarzających się lub sekwencyjnych wzorców.',
    'vault_init_failed_prefix': 'Inicjalizacja skarbca nie powiodła się',
    'create_vault_title': 'UTWÓRZ SWÓJ ZASZYFROWANY SKARBIEC',
    'create_vault_subtitle': 'Ustaw swój klucz główny, aby wygenerować\nswoją kryptograficzną tożsamość P2P',
    'set_decryption_key_label': 'Ustaw Klucz Deszyfrowania',
    'strength_too_weak': 'Za słabe',
    'strength_weak': 'Słabe',
    'strength_medium': 'Średnie',
    'strength_strong': 'Silne',
    'strength_very_strong': 'Bardzo silne',
    'initialize_vault_button': 'ZAINICJUJ SKARBIEC',
    'footer_privacy_text': 'Zaprojektowano z szyfrowaniem Zero-Knowledge klasy wojskowej.\nCała komunikacja działa wyłącznie w trybie Peer-to-Peer (P2P).\nWiadomości automatycznie samozniszczają się po 24 godzinach\nprzy użyciu bezpiecznego czyszczenia pamięci bez śladów.\nZero śladów, zero dzienników, pełna prywatność.',
    'vault_not_initialized_device': 'Skarbiec nie został zainicjowany na tym urządzeniu.',
    'invalid_decryption_key': 'Nieprawidłowy klucz deszyfrowania.',
    'vault_data_corrupted': 'Dane skarbca są uszkodzone (klucz był poprawny, ale sam plik skarbca jest uszkodzony).',
    'decrypt_padlock_title': 'ODSZYFRUJ SWÓJ PADLOCK',
    'login_subtitle': 'ZAPROJEKTOWANO Z SZYFROWANIEM ZERO-KNOWLEDGE\nKLASY WOJSKOWEJ',
    'enter_decryption_key_label': 'Wprowadź Klucz Deszyfrowania',
    'access_vault_button': 'OTWÓRZ SKARBIEC',
  },
};

// Lista única de idiomas suportados - usada em todos os sítios que mostram
// um seletor de idioma (menu "..." e Settings > App Language), para nunca
// mais ficarem dessincronizados um do outro.
const List<Map<String, String>> kSupportedLanguages = [
  {'code': 'EN', 'name': 'English', 'flag': '🇺🇸'},
  {'code': 'PT', 'name': 'Português', 'flag': '🇵🇹'},
  {'code': 'ES', 'name': 'Español', 'flag': '🇪🇸'},
  {'code': 'FR', 'name': 'Français', 'flag': '🇫🇷'},
  {'code': 'DE', 'name': 'Deutsch', 'flag': '🇩🇪'},
  {'code': 'IT', 'name': 'Italiano', 'flag': '🇮🇹'},
  {'code': 'RU', 'name': 'Русский', 'flag': '🇷🇺'},
  {'code': 'UK', 'name': 'Українська', 'flag': '🇺🇦'},
  {'code': 'ZH', 'name': '中文', 'flag': '🇨🇳'},
  {'code': 'JA', 'name': '日本語', 'flag': '🇯🇵'},
  {'code': 'KO', 'name': '한국어', 'flag': '🇰🇷'},
  {'code': 'AR', 'name': 'العربية', 'flag': '🇸🇦'},
  {'code': 'HI', 'name': 'हिन्दी', 'flag': '🇮🇳'},
  {'code': 'NL', 'name': 'Nederlands', 'flag': '🇳🇱'},
  {'code': 'PL', 'name': 'Polski', 'flag': '🇵🇱'},
  {'code': 'TR', 'name': 'Türkçe', 'flag': '🇹🇷'},
];

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
   int _lastNotifiedTimestamp = 0;
  String _username = "Carregando...";
  int _currentIndex = 0;
  String _myPrivacyId = '';
  String _destructTime = '7 Days';
  // MainNavigationScreen só é construído UMA VEZ (empurrado pelo Navigator a
  // partir do Login/Setup) - widget.currentLanguage nunca muda depois disso,
  // por isso este ecrã precisa do seu próprio estado para refletir a troca
  // de idioma feita nos diálogos abaixo sem teres de sair e voltar a entrar.
  late String _currentLang;

  bool _silentMode = false;
  bool _passcodeLock = false;
  bool _blockScreenshots = true;

  final List<Map<String, dynamic>> _chats = [];

  final List<Map<String, String>> _contacts = [];
@override
  void initState() {
    super.initState();
    _currentLang = widget.currentLanguage;

    PadlockNetwork.connect();
    WidgetsBinding.instance.addObserver(this);
    _generateNewId();
     _loadUsername(); // Chama a função para ler o nome
    _loadStoredData(); // Carrega os contactos e mensagens do cofre
    _silentMode = !(Hive.box('padlock_vault').get('notifications_enabled', defaultValue: true) as bool);
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
    final local = t[_currentLang] ?? t['EN']!;
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
            // Inglês por agora (a base da app, antes da tradução completa
            // ficar pronta) - o resto do texto do ecrã já segue esta
            // mesma regra. Estilo igual ao resto da app: gradiente verde
            // (claro para escuro) com borda mais clara por cima.
            builder: (context) => Dialog(
              backgroundColor: Colors.transparent,
              child: Container(
                padding: const EdgeInsets.all(20),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(16),
                  gradient: const LinearGradient(
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                    colors: [Color(0xFF1e4d2b), Color(0xFF0a1a12)],
                  ),
                  border: Border.all(color: Colors.greenAccent.withValues(alpha: 0.4)),
                ),
                child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text('Edit Contact', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 16)),
                  const SizedBox(height: 16),
                  TextField(
                    controller: controller,
                    style: const TextStyle(color: Colors.white),
                    decoration: InputDecoration(
                      labelText: 'Name',
                      labelStyle: const TextStyle(color: Colors.grey),
                      enabledBorder: OutlineInputBorder(borderSide: const BorderSide(color: Colors.grey), borderRadius: BorderRadius.circular(8)),
                      focusedBorder: const OutlineInputBorder(borderSide: BorderSide(color: Colors.greenAccent), borderRadius: BorderRadius.all(Radius.circular(8))),
                    ),
                  ),
                  const SizedBox(height: 16),
                  Row(
                mainAxisAlignment: MainAxisAlignment.end,
                children: [
                TextButton(
                  onPressed: () => Navigator.pop(context),
                  child: const Text('Cancel', style: TextStyle(color: Colors.grey)),
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
            child: const Text('Save', style: TextStyle(color: Colors.greenAccent, fontWeight: FontWeight.bold)),
          ),
                ],
              ),
                ],
              ),
              ),
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
        currentLang: _currentLang,
        destructTime: _destructTime,
        silentMode: _silentMode,
        passcodeLock: _passcodeLock,
        blockScreenshots: _blockScreenshots,
        onLangChange: (lang) => setState(() => _currentLang = lang),
        onDestructChange: (time) => setState(() => _destructTime = time),
        // Só existe o Silent Mode agora - ter dois botões (Notifications e
        // Silent Mode) a controlar exatamente a mesma coisa por baixo não
        // fazia sentido nenhum, era só confuso.
        onSilentChange: (val) {
          setState(() => _silentMode = val);
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
            // Mesma lista única usada em Settings (kSupportedLanguages) -
            // antes esta lista tinha idiomas diferentes e nomes escritos em
            // português em vez da escrita própria de cada língua. O título
            // agora só mostra a palavra "Language" no idioma atual, nunca
            // as duas ao mesmo tempo (faltava a chave 'language' na tabela
            // de traduções, por isso caía sempre no texto fixo "Idioma /
            // Language").
            builder: (context) => Dialog(
              backgroundColor: Colors.transparent,
              child: Container(
                padding: const EdgeInsets.all(20),
                constraints: const BoxConstraints(maxHeight: 480),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(16),
                  gradient: const LinearGradient(
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                    colors: [Color(0xFF1e4d2b), Color(0xFF0a1a12)],
                  ),
                  border: Border.all(color: Colors.greenAccent.withValues(alpha: 0.4)),
                ),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      t[_currentLang]?['language'] ?? 'Language',
                      style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 16),
                    ),
                    const SizedBox(height: 12),
                    Flexible(
                      child: SizedBox(
                        width: double.maxFinite,
                        child: ListView(
                          shrinkWrap: true,
                          children: kSupportedLanguages.map((lang) {
                            final isSelected = lang['code'] == _currentLang;
                            return ListTile(
                              leading: Text(lang['flag']!, style: const TextStyle(fontSize: 20)),
                              title: Text(
                                lang['name']!,
                                style: TextStyle(
                                  color: isSelected ? Colors.greenAccent : const Color(0xFFe4efe6),
                                  fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
                                ),
                              ),
                              trailing: isSelected ? const Icon(Icons.check, color: Colors.greenAccent) : null,
                              onTap: () {
                                context.findAncestorStateOfType<_PadlockAppState>()?._changeLanguage(lang['code']!);
                                setState(() => _currentLang = lang['code']!);
                                Navigator.pop(context);
                              },
                            );
                          }).toList(),
                        ),
                      ),
                    ),
                  ],
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
            return t[lang]?['chats'] ?? 'Chats';
          }()),
        ),
        BottomNavigationBarItem(
          icon: const Icon(Icons.people_outline),
          activeIcon: const Icon(Icons.chat_bubble, color: Color(0xFF00FF66)),
          label: (() {
            final padlock = context.findAncestorStateOfType<_PadlockAppState>();
            final lang = padlock?._currentLanguage ?? 'EN';
            return t[lang]?['contacts'] ?? 'Contacts';
          }()),
        ),
        BottomNavigationBarItem(
          icon: const Icon(Icons.settings_outlined),
          activeIcon: const Icon(Icons.chat_bubble, color: Color(0xFF00FF66)),
          label: (() {
            final padlock = context.findAncestorStateOfType<_PadlockAppState>();
            final lang = padlock?._currentLanguage ?? 'EN';
            return t[lang]?['settings'] ?? 'Settings';
          }()),
        ),
        BottomNavigationBarItem(
          icon: const Icon(Icons.person_outline),
          activeIcon: const Icon(Icons.chat_bubble, color: Color(0xFF00FF66)),
          label: (() {
            final padlock = context.findAncestorStateOfType<_PadlockAppState>();
            final lang = padlock?._currentLanguage ?? 'EN';
            return t[lang]?['profile'] ?? 'Profile';
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
            
            Text(local['encrypted_p2p_message_preview']!, maxLines: 1, overflow: TextOverflow.ellipsis, style: const TextStyle(color: Colors.lightBlueAccent)),
            const SizedBox(height: 4),
            Row(
              children: [
                const Icon(Icons.timer_outlined, size: 12, color: Colors.redAccent),
                const SizedBox(width: 4),
                Text('${local['autodestruct']} 24h', style: const TextStyle(color: Colors.redAccent, fontSize: 11)),
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
              title: Text(local['delete_chat_confirm_title']!, style: const TextStyle(color: Colors.white)),
              content: Text(local['delete_chat_confirm_body']!, style: const TextStyle(color: Color.fromARGB(255, 122, 241, 232))),
              actions: [
                TextButton(
                  onPressed: () => Navigator.pop(context),
                  child: Text(local['cancel_button']!, style: const TextStyle(color: Color.fromARGB(255, 240, 206, 155))),
                ),
                TextButton(
                  onPressed: () {
                    Navigator.pop(context);
                    chats.removeAt(index);
                    // ATENÇÃO: Se tinhas mais alguma linha de código aqui (como um setState) para atualizar a lista, volta a colocá-la.
                  },
                  child: Text(local['delete_button']!, style: const TextStyle(color: Color(0xFFFF1515))),
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
  final Map<String, String> local;
  const VoiceMessageBubble({super.key, required this.audioBase64, required this.isMe, required this.local});

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
        Text(widget.local['voice_message_label']!, style: TextStyle(color: color, fontSize: 13)),
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
                title: Text(widget.local['copy_message']!, style: const TextStyle(color: Colors.white)),
                onTap: () {
                  Clipboard.setData(ClipboardData(text: msg['text']));
                  Navigator.pop(context); // Fecha o menu
                },
              ),
              const Divider(color: Colors.white10),
              ListTile(
                leading: const Icon(Icons.delete_outline, color: Colors.redAccent),
                title: Text(widget.local['destroy_message']!, style: const TextStyle(color: Colors.redAccent)),
                onTap: () {
                  Navigator.pop(context); // Fecha o menu principal

                  // Pergunta de confirmação antes de apagar de vez
                  showDialog(
                    context: context,
                    builder: (ctx) => AlertDialog(
                      backgroundColor: const Color(0xFF151515),
                      title: Text(widget.local['node_destruction_title']!, style: const TextStyle(color: Colors.white)),
                      content: Text(widget.local['destroy_message_confirm_body']!, style: const TextStyle(color: Colors.grey)),
                      actions: [
                        TextButton(
                          onPressed: () => Navigator.pop(ctx),
                          child: Text(widget.local['cancel_button']!, style: const TextStyle(color: Colors.grey)),
                        ),
                        TextButton(
                          onPressed: () {
                            Navigator.pop(ctx);
                            _deleteMessage(msg['timestamp']); // Executa a destruição!
                          },
                          child: Text(widget.local['destroy_button']!, style: const TextStyle(color: Colors.redAccent)),
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
          'text': widget.local['encrypted_photo_sent_message']!,
          'isMe': true,
          'status': 'sent',
          'timestamp': currentTimestamp,
        });
        widget.chatData['msg'] = widget.local['photo_chat_preview']!;
        widget.chatData['time'] = widget.local['just_now']!;
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
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('${widget.local['failed_to_send_photo_prefix']}: $e')));
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
            'text': widget.local['voice_message_chat_preview']!,
            'audioBase64': base64Encode(bytes),
            'isMe': true,
            'status': 'sent',
            'timestamp': currentTimestamp,
          });
          widget.chatData['msg'] = widget.local['voice_message_chat_preview']!;
          widget.chatData['time'] = widget.local['just_now']!;
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
          ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('${widget.local['failed_to_send_voice_prefix']}: $e')));
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
          SnackBar(content: Text((widget.local['no_secure_channel_error'] ?? 'Could not send: no secure channel with this contact yet ({error}). Try removing and re-adding them.').replaceAll('{error}', '$e'))),
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
      widget.chatData['time'] = widget.local['just_now']!;
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
  widget.local['encrypted_p2p_channel']!,
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
          title: Text(widget.local['block_id_title']!, style: const TextStyle(color: Colors.white)),
          content: Text(widget.local['block_id_confirm_body']!, style: const TextStyle(color: Colors.white70)),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: Text(widget.local['cancel_button']!, style: const TextStyle(color: Colors.grey)),
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
                      child: Text(widget.local['block_button']!, style: const TextStyle(color: Colors.red)),
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
                  SnackBar(
                    content: Text(widget.local['keys_not_available']!, style: const TextStyle(color: Colors.white)),
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
                    title: Text(
                      widget.local['safety_number_title']!,
                      style: const TextStyle(color: Colors.greenAccent, fontWeight: FontWeight.bold)
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
                        Text(
                          widget.local['safety_number_desc']!,
                          style: const TextStyle(color: Colors.white70, fontSize: 12),
                          textAlign: TextAlign.center,
                        ),
                      ],
                    ),
                    actions: [
                      TextButton(
                        onPressed: () => Navigator.pop(ctx),
                        child: Text(widget.local['close_button']!, style: const TextStyle(color: Colors.greenAccent))
                      ),
                    ],
                  ),
                );
              });
            },
            child: Text(widget.local['verify_safety_number']!, style: const TextStyle(color: Colors.greenAccent)),
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
                          title: Text(widget.local['destruct_1m']!, style: const TextStyle(color: Colors.white)),
                          onTap: () {
                            setState(() { widget.chatData['destructTime'] = '1m'; });
                            widget.onUpdate();
                            Hive.box('padlock_vault').put(widget.chatData['id'], widget.chatData);
                            try { PadlockNetwork.channel?.sink.add(jsonEncode({'type': 'update_timer', 'targetId': widget.chatData['id'], 'time': '1m'})); } catch (e) {}
                            Navigator.pop(context);
                          },
                        ),
                        ListTile(
                          title: Text(widget.local['destruct_5m']!, style: const TextStyle(color: Colors.white)),
                          onTap: () {
                            setState(() { widget.chatData['destructTime'] = '5m'; });
                            widget.onUpdate();
                            Hive.box('padlock_vault').put(widget.chatData['id'], widget.chatData);
                            try { PadlockNetwork.channel?.sink.add(jsonEncode({'type': 'update_timer', 'targetId': widget.chatData['id'], 'time': '5m'})); } catch (e) {}
                            Navigator.pop(context);
                          },
                        ),
                        ListTile(
                          title: Text(widget.local['destruct_1h']!, style: const TextStyle(color: Colors.white)),
                          onTap: () {
                            setState(() { widget.chatData['destructTime'] = '1h'; });
                            widget.onUpdate();
                            Hive.box('padlock_vault').put(widget.chatData['id'], widget.chatData);
                            try { PadlockNetwork.channel?.sink.add(jsonEncode({'type': 'update_timer', 'targetId': widget.chatData['id'], 'time': '1h'})); } catch (e) {}
                            Navigator.pop(context);
                          },
                        ),
                        ListTile(
                          title: Text(widget.local['destruct_24h']!, style: const TextStyle(color: Colors.white)),
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
      VoiceMessageBubble(audioBase64: m['audioBase64'], isMe: isMe, local: widget.local)
    else
      Text(
      m['text'] == '[Message not decrypted]' ? (widget.local['message_not_decrypted'] ?? m['text']) : m['text'],
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
                hintText: local['search_contact_hint'],
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
                          subtitle: Text(
  local['encrypted_p2p_contact']!,
  style: const TextStyle(
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
  final bool silentMode;
  final bool passcodeLock;
  final bool blockScreenshots;

  final Function(String) onLangChange;
  final Function(String) onDestructChange;
  final Function(bool) onSilentChange;
  final Function(bool) onPasscodeChange;
  final Function(bool) onScreenshotsChange;

  const SettingsScreen({
    super.key,
    required this.local,
    required this.currentLang,
    required this.destructTime,
    required this.silentMode,
    required this.passcodeLock,
    required this.blockScreenshots,
    required this.onLangChange,
    required this.onDestructChange,
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
            child: Center(
              child: Text(
                local['settings_header']!,
                style: const TextStyle(
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
                _buildSectionTitle(local['section_core_security']!, Colors.greenAccent),
                _buildInfoTile(Icons.shield, local['info_encryption_title']!, local['info_encryption_desc']!),
                _buildInfoTile(Icons.wifi_tethering, local['info_p2p_title']!, local['info_p2p_desc']!),
                _buildInfoTile(Icons.timer_off, local['info_autodestruct_title']!, local['info_autodestruct_desc']!),
                _buildInfoTile(Icons.phonelink_erase, local['info_screenshot_title']!, local['info_screenshot_desc']!),
                _buildInfoTile(Icons.lock_clock, local['info_timeout_title']!, local['info_timeout_desc']!),

                const Divider(color: Colors.white10, height: 35),

                _buildSectionTitle(local['section_premium']!, Colors.amber),
                _buildPremiumTile(context, local),

                const Divider(color: Colors.white10, height: 35),

                _buildSectionTitle(local['section_help_center']!, Colors.greenAccent),
                _buildHelpTile(context, Icons.folder_copy_rounded, local['help_vault_files_q']!, local['help_vault_files_a']!),
                _buildHelpTile(context, Icons.person_add, local['help_add_contact_q']!, local['help_add_contact_a']!),
                _buildHelpTile(context, Icons.share, local['help_share_id_q']!, local['help_share_id_a']!),
                _buildHelpTile(context, Icons.edit, local['help_rename_contact_q']!, local['help_rename_contact_a']!),
                _buildHelpTile(context, Icons.person_remove, local['help_delete_contact_q']!, local['help_delete_contact_a']!),
                _buildHelpTile(context, Icons.delete_sweep, local['help_wipe_chat_q']!, local['help_wipe_chat_a']!),

                const Divider(color: Colors.white10, height: 35),

                _buildSectionTitle(local['section_app_preferences']!, Colors.greenAccent),
                ListTile(
                  leading: const Icon(Icons.language, color: Color(0xFF1e4d2b)),
                  title: Text(local['app_language_title']!, style: const TextStyle(color: Colors.white)),
                  subtitle: Text('${local['current_lang_prefix']}: $currentLang', style: const TextStyle(color: Colors.grey, fontSize: 11)),
                  trailing: const Icon(Icons.chevron_right, color: Colors.grey),
                  onTap: () => _showLanguageDialog(context),
                ),
                // Só um botão agora - ter "Push Notifications" e "Silent
                // Mode" separados não fazia sentido, os dois controlavam
                // exatamente o mesmo interruptor por baixo. Ligado = corta
                // notificações E toques de chamada; desligado = toca tudo.
                SwitchListTile(
                  secondary: const Icon(Icons.volume_off, color: Color(0xFF1e4d2b)),
                  title: const Text('Silent Mode', style: TextStyle(color: Colors.white)),
                  subtitle: Text(local['silent_mode_desc']!, style: const TextStyle(fontSize: 11, color: Colors.grey)),
                  value: silentMode,
                  activeTrackColor: const Color(0xFF1e4d2b),
                  onChanged: onSilentChange,
                ),

                const Divider(color: Colors.white10, height: 35),

                _buildSectionTitle(local['section_panic_room']!, Colors.redAccent),
                ListTile(
                  leading: const Icon(Icons.warning_amber_rounded, color: Colors.redAccent, size: 30),
                  title: Text(local['nuke_vault_title']!, style: const TextStyle(color: Colors.redAccent, fontWeight: FontWeight.bold, fontSize: 14)),
                  subtitle: Padding(
                    padding: const EdgeInsets.only(top: 6.0),
                    child: Text(local['nuke_vault_desc']!, style: const TextStyle(color: Colors.grey, fontSize: 11, height: 1.4)),
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
                        title: Row(
                          children: [
                            const Icon(Icons.dangerous, color: Colors.redAccent),
                            const SizedBox(width: 10),
                            Text(local['critical_warning_title']!, style: const TextStyle(color: Colors.redAccent, fontWeight: FontWeight.bold, fontSize: 16)),
                          ],
                        ),
                        content: Text(
                          local['nuke_confirm_body']!,
                          style: const TextStyle(color: Colors.white70, height: 1.4),
                        ),
                        actions: [
                          TextButton(
                            onPressed: () => Navigator.pop(ctx),
                            child: Text(local['cancel_button']!.toUpperCase(), style: const TextStyle(color: Colors.grey)),
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
                            child: Text(local['nuke_everything_button']!, style: const TextStyle(color: Colors.redAccent, fontWeight: FontWeight.bold)),
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

  Widget _buildPremiumTile(BuildContext context, Map<String, String> local) {
    return ListTile(
      contentPadding: EdgeInsets.zero,
      leading: const Text('💎', style: TextStyle(fontSize: 24)),
      title: Row(
        children: [
          Text(local['secure_crypto_vault_title']!, style: const TextStyle(color: Colors.lightBlueAccent, fontWeight: FontWeight.bold, fontSize: 15)),
          const SizedBox(width: 8),
          const Icon(Icons.lock, color: Colors.greenAccent, size: 16),
        ],
      ),
      subtitle: Padding(
        padding: const EdgeInsets.only(top: 4.0),
        child: Text(local['crypto_vault_desc']!, style: const TextStyle(color: Colors.white60, fontSize: 11)),
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
                child: Text(local['got_it_button']!, style: const TextStyle(color: Colors.lightBlueAccent)),
              ),
            ],
          ),
        );
      },
    );
  }

  void _showLanguageDialog(BuildContext context) {
    // Mesma lista única usada no menu "..." (kSupportedLanguages) - antes
    // esta tinha só 11 idiomas enquanto a do menu "..." tinha 16, e nenhuma
    // marcava qual estava escolhido.
    showDialog(
      context: context,
      builder: (ctx) => Dialog(
        backgroundColor: Colors.transparent,
        child: Container(
          padding: const EdgeInsets.all(20),
          constraints: const BoxConstraints(maxHeight: 480),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(16),
            gradient: const LinearGradient(
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
              colors: [Color(0xFF1e4d2b), Color(0xFF0a1a12)],
            ),
            border: Border.all(color: Colors.greenAccent.withValues(alpha: 0.4)),
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                t[currentLang]?['language'] ?? 'Language',
                style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 16),
              ),
              const SizedBox(height: 12),
              Flexible(
                child: SizedBox(
                  width: double.maxFinite,
                  child: ListView.builder(
                    shrinkWrap: true,
                    itemCount: kSupportedLanguages.length,
                    itemBuilder: (context, index) {
                      final lang = kSupportedLanguages[index];
                      final isSelected = lang['code'] == currentLang;
                      return ListTile(
                        leading: Text(lang['flag']!, style: const TextStyle(fontSize: 20)),
                        title: Text(
                          lang['name']!,
                          style: TextStyle(
                            color: isSelected ? Colors.greenAccent : const Color(0xFFe4efe6),
                            fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
                          ),
                        ),
                        trailing: isSelected ? const Icon(Icons.check, color: Colors.greenAccent) : null,
                        onTap: () {
                          final code = lang['code']!;
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
            ],
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
                child: Text(currentT['close_button'] ?? 'Close', style: const TextStyle(color: Colors.white70)),
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
              builder: (context) => Dialog(
                backgroundColor: Colors.transparent,
                child: Container(
                  padding: const EdgeInsets.all(20),
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(16),
                    gradient: const LinearGradient(
                      begin: Alignment.topLeft,
                      end: Alignment.bottomRight,
                      colors: [Color(0xFF1e4d2b), Color(0xFF0a1a12)],
                    ),
                    border: Border.all(color: Colors.greenAccent.withValues(alpha: 0.4)),
                  ),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(local['edit_name_title']!, style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 16)),
                      const SizedBox(height: 16),
                      TextField(
                        controller: controller,
                        style: const TextStyle(color: Colors.white),
                        decoration: InputDecoration(
                          labelText: local['username_label'],
                          labelStyle: const TextStyle(color: Colors.grey),
                          enabledBorder: OutlineInputBorder(borderSide: const BorderSide(color: Colors.grey), borderRadius: BorderRadius.circular(8)),
                          focusedBorder: const OutlineInputBorder(borderSide: BorderSide(color: Colors.greenAccent), borderRadius: BorderRadius.all(Radius.circular(8))),
                        ),
                      ),
                      const SizedBox(height: 16),
                      Row(
                        mainAxisAlignment: MainAxisAlignment.end,
                        children: [
                          TextButton(
                            onPressed: () => Navigator.pop(context),
                            child: Text(local['cancel_button']!, style: const TextStyle(color: Colors.grey)),
                          ),
                          TextButton(
                            onPressed: () {
                              if (controller.text.trim().isNotEmpty) {
                                onUpdateUsername(controller.text.trim());
                              }
                              Navigator.pop(context);
                            },
                            child: Text(local['save_button']!, style: const TextStyle(color: Colors.greenAccent, fontWeight: FontWeight.bold)),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
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
              _buildActionButton(Icons.qr_code, local['qr_code_button']!, () => _showQrDialog(context), color: Colors.lightBlueAccent),
              _buildActionButton(Icons.copy, local['copy_id_button']!, () {
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
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      // O Diamante gigante
                      const Text('💎', style: TextStyle(fontSize: 22)),
                      const SizedBox(height: 2),
                      // O texto em Branco Pérola no fundo
                      Text(
                        local['secure_crypto_vault_short']!,
                        style: const TextStyle(
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
                      MaterialPageRoute(builder: (context) => VaultFilesGateScreen(local: local)),
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
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        const Icon(Icons.folder_copy_rounded, color: Colors.lightBlueAccent, size: 28),
                        const SizedBox(height: 2),
                        Text(
                          local['secure_vault_files_short']!,
                          style: const TextStyle(
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
           Text(
      local['privacy_id_label']!,
      textAlign: TextAlign.center,
      style: const TextStyle(fontSize: 13, fontWeight: FontWeight.bold, color: Colors.white70),
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
    Text(
      local['bio_label']!,
      textAlign: TextAlign.center,
      style: const TextStyle(fontSize: 13, fontWeight: FontWeight.bold, color: Colors.white70),
    ),
    const SizedBox(height: 6),
    Text(
      local['profile_bio_paragraph']!,
      textAlign: TextAlign.center,
      style: const TextStyle(fontSize: 12, color: Colors.white, height: 1.4),
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
  Map<String, String> get _local => widget.local ?? t['EN']!;
  Timer? _callTimeoutTimer;
  Timer? _activeCallTimer;
  Timer? _ringingTimer; // Temporizador para o som do tuuu... tuuu
  int _secondsElapsed = 0;
  bool _callHandled = false;
  bool _isEnding = false;
  bool _isMuted = false;
  bool _isSpeakerOn = false;
  final AudioPlayer _audioPlayer = AudioPlayer();

  String _callStatusText = '';
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
    _callStatusText = _local['call_status_connecting']!;
    PadlockNetwork.emChamada = true;
    WakelockPlus.enable();
    // O altifalante liga sempre ao início em vídeo (ver o resto da lógica
    // em _setupPeerConnectionListeners) - o botão tem de nascer já a
    // refletir isso, senão mostrava "desligado" com o altifalante já ligado.
    _isSpeakerOn = widget.isVideo;
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
            _callStatusText = _local['call_status_exchanging_keys']!;
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
              _callStatusText = _local['call_status_ringing']!;
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
        _callStatusText = _local['call_status_connecting_encrypted']!;
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
            SnackBar(content: Text(_local['call_contact_unavailable']!, style: const TextStyle(color: Colors.red))),
          );
        }
      });
      
    } else {
      setState(() {
        _callStatusText = _local['call_status_incoming_encrypted']!;
        _callStatusColor = const Color(0xFF00FF66);
      });
      _startMissedCallTimer();
    Future.delayed(const Duration(milliseconds: 1500), () {
     final ringingSignal = {
  'action': 'call_ringing',
  'targetId': widget.targetId,
};
// Usa PadlockNetwork.channel ao vivo, nunca o "widget.channel" capturado
      // na criação do ecrã - ver explicação completa mais abaixo, junto de
      // _fetchIceServers.
      PadlockNetwork.channel?.sink.add(jsonEncode(ringingSignal));
});
// Aciona o toque para quem recebe a chamada (com o nome exato do teu
// ficheiro) - só se o Silent Mode estiver desligado. Antes tocava sempre,
// sem olhar nenhuma para essa definição.
final bool silentModeAtivo = !(Hive.box('padlock_vault').get('notifications_enabled', defaultValue: true) as bool);
if (!widget.acceptedViaCallKit && !silentModeAtivo) {
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
          _callStatusText = '${_local['call_status_connected_prefix']} ($minutes:$seconds)';
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
      final missedLabel = _local['missed_secure_call']!;
      final missedMsg = '📞 $missedLabel ($timeStr)';

      if (chatIdx != -1) {
        if (allChats[chatIdx]['messages'] == null) allChats[chatIdx]['messages'] = [];
        allChats[chatIdx]['messages'].add({'text': missedMsg, 'isMe': false, 'status': 'missed', 'timestamp': now});
        allChats[chatIdx]['msg'] = '📞 $missedLabel';
        allChats[chatIdx]['time'] = timeStr;
        allChats[chatIdx]['unread'] = (allChats[chatIdx]['unread'] ?? 0) + 1;
      }
      vault.put('chats', jsonEncode(allChats));
      flutterLocalNotificationsPlugin.show(DateTime.now().millisecond, 'Padlock - ${_local['missed_call_notification_title']}', missedMsg, const NotificationDetails(android: AndroidNotificationDetails('padlock_msg_channel', 'Secure Messages', importance: Importance.max, priority: Priority.high, playSound: true)));
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
          _callStatusText = _local['call_status_connected_encrypted']!;
          _callStatusColor = const Color(0xFF00FF66);
          _startActiveTimer();
          _audioPlayer.stop(); // Corta o Morse/Ringing imediatamente assim que atende!
          // A chamada atendeu! Em voz, passa o som para o ouvido (auscultador).
          // Em vídeo mantém-se sempre no altifalante - faltava este "isVideo"
          // aqui, por isso o altifalante ligado no início da chamada de
          // vídeo era sempre desligado outra vez assim que a ligação
          // completava, obrigando a ligá-lo à mão.
        if (_localStream != null && _localStream!.getAudioTracks().isNotEmpty) {
  _localStream!.getAudioTracks()[0].enableSpeakerphone(widget.isVideo);
  _isSpeakerOn = widget.isVideo;
}
        } else if (state == RTCIceConnectionState.RTCIceConnectionStateDisconnected) {
          // EFEITO TÚNEL: Net caiu. Não desliga a chamada, espera que recupere.
          _callStatusText = _local['call_status_reconnecting']!;
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
      PadlockNetwork.channel?.sink.add(jsonEncode(candidateSignal));
    };
  }

  // Pede a configuração TURN ao servidor em vez de a ter fixa no APK
  // (credenciais fixas no cliente eram extraíveis por descompilação).
  //
  // Bug encontrado: com um limite de só 4 segundos e SEM TURN nenhum na
  // lista de reserva (só STUN), uma ligação de dados móveis mais lenta a
  // pedir isto logo no início da chamada facilmente estourava o tempo -
  // caindo para STUN sozinho, que não consegue atravessar duas redes
  // móveis com NAT restritivo ao mesmo tempo (funciona com Wi-Fi de um dos
  // lados porque routers de casa costumam ter NAT mais simples). É a
  // explicação mais provável para "dados móveis com dados móveis" ficar
  // sempre preso em "Exchanging Encryption Keys" sem nunca ligar.
  //
  // Segundo bug encontrado (mais grave): o envio de sinalização inteiro
  // nesta classe (oferta, resposta, candidatos, pedido de ICE, fim de
  // chamada)
  // usava "widget.channel" - uma "fotografia" do PadlockNetwork.channel
  // tirada no preciso instante em que o ecrã de chamada foi criado. Numa
  // rede móvel, é muito comum o WebSocket cair e voltar a ligar sozinho a
  // meio de uma chamada (mudança de torre, o telefone poupar bateria,
  // etc.) - quando isso acontece, PadlockNetwork.channel passa a apontar
  // para a ligação NOVA, mas o ecrã de chamada continuava agarrado à
  // ligação VELHA e já morta, perdendo a capacidade de mandar candidatos
  // novos (ou até a própria resposta) para sempre, mesmo com a rede já
  // recuperada. Agora todos os pontos usam PadlockNetwork.channel
  // diretamente, sempre a versão viva.
  Future<List<Map<String, dynamic>>> _fetchIceServers() async {
    final fallback = PadlockNetwork.cachedIceServers ??
        <Map<String, dynamic>>[{'urls': 'stun:stun.l.google.com:19302'}];
    if (PadlockNetwork.channel == null) return fallback;

    Future<List<Map<String, dynamic>>?> attempt() async {
      try {
        final completer = Completer<List<Map<String, dynamic>>?>();
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
        PadlockNetwork.channel?.sink.add(jsonEncode({'type': 'get_ice_servers'}));
        final result = await completer.future.timeout(
          const Duration(seconds: 8),
          onTimeout: () => null,
        );
        await sub.cancel();
        return result;
      } catch (e) {
        return null;
      }
    }

    // Uma tentativa extra antes de desistir - uma rede móvel mais lenta ou
    // um WebSocket ainda a acabar de ligar pode perfeitamente falhar a
    // primeira vez e responder bem na segunda.
    final result = await attempt() ?? await attempt();
    if (result != null) {
      PadlockNetwork.cachedIceServers = result;
      return result;
    }
    return fallback;
  }

  Future<void> startSecureCall(String targetPrivacyId) async {
    var status = await Permission.microphone.request();
    if (status != PermissionStatus.granted) return;
    if (!mounted) return;
    setState(() {
      _callStatusText = _local['call_status_connecting_encrypted']!;
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
      PadlockNetwork.channel?.sink.add(jsonEncode(callSignal));
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
      _callStatusText = _local['call_status_exchanging_keys']!;
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
      PadlockNetwork.channel?.sink.add(jsonEncode(answerSignal));
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
    PadlockNetwork.channel?.sink.add(jsonEncode(endSignal));
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
  Map<String, String> get _local => t[context.findAncestorStateOfType<_PadlockAppState>()?._currentLanguage ?? 'EN'] ?? t['EN']!;

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
        SnackBar(content: Text(_local['setup_code_too_weak']!)),
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
          SnackBar(content: Text('${_local['vault_init_failed_prefix']}: $e')),
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
              Text(
                _local['create_vault_title']!,
                textAlign: TextAlign.center,
                style: const TextStyle(
                  color: Colors.white,
                  fontSize: 18,
                  fontWeight: FontWeight.bold,
                  letterSpacing: 1.2,
                ),
              ),
              const SizedBox(height: 12),
              Text(
                _local['create_vault_subtitle']!,
                textAlign: TextAlign.center,
                style: const TextStyle(color: Colors.grey, fontSize: 11, height: 1.3),
              ),
              const SizedBox(height: 32),
              TextField(
                controller: _keyController,
                obscureText: _obscureText,
                style: const TextStyle(color: Colors.white),
                decoration: InputDecoration(
                  labelText: _local['set_decryption_key_label'],
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
                  final labels = [_local['strength_too_weak']!, _local['strength_weak']!, _local['strength_medium']!, _local['strength_strong']!, _local['strength_very_strong']!];
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
                      : Text(
                          _local['initialize_vault_button']!,
                          style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
                        ),
                ),
              ),
              const SizedBox(height: 36),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 10.0),
                child: Text(
                  _local['footer_privacy_text']!,
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
  Map<String, String> get _local => t[context.findAncestorStateOfType<_PadlockAppState>()?._currentLanguage ?? 'EN'] ?? t['EN']!;

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
          SnackBar(content: Text(_local['vault_not_initialized_device']!)),
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
        throw Exception(_local['invalid_decryption_key']!);
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
        throw Exception(_local['vault_data_corrupted']!);
      }

      PadlockNetwork.isUnlocked = true;
      if (PadlockNetwork.pendingFcmToken != null) {
        await Hive.box('padlock_vault').put('my_fcm_token', PadlockNetwork.pendingFcmToken);
      }

      if (mounted) {
        final pendingCall = PadlockNetwork.pendingCallData;
        // O idioma escolhido vive em _PadlockAppState (lido do SharedPreferences
        // no arranque) - sem isto, todo o login normal (não só o primeiro
        // arranque) reconstruía o ecrã principal sempre fixo em inglês,
        // ignorando por completo o idioma que a pessoa tinha escolhido.
        final padlockLang = context.findAncestorStateOfType<_PadlockAppState>()?._currentLanguage ?? 'EN';
        // Vai sempre para o ecrã principal primeiro - mesmo havendo uma
        // chamada à espera. Antes, a chamada substituía o ecrã de login
        // como única rota, sem nada por baixo para onde voltar; agora ela
        // é mostrada por cima (ver PadlockCallOverlay), com o ecrã
        // principal já pronto por baixo para quando ela for minimizada ou
        // terminar.
        Navigator.of(context).pushReplacement(
          MaterialPageRoute(builder: (context) => MainNavigationScreen(currentLanguage: padlockLang, onLanguageChange: (lang) {})),
        );
        if (pendingCall != null) {
          // Havia uma chamada à espera (aceite via CallKit com a app morta).
          PadlockCallOverlay.show(ActiveCallScreen(
            local: t[padlockLang] ?? t['EN']!,
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
              Text(
                _local['decrypt_padlock_title']!,
                textAlign: TextAlign.center,
                style: const TextStyle(
                  color: Colors.white,
                  fontSize: 18,
                  fontWeight: FontWeight.bold,
                  letterSpacing: 1.2,
                ),
              ),
              const SizedBox(height: 12),

              // Subtítulo (Opção 2 com quebra de linha para telemóvel)
              Text(
                _local['login_subtitle']!,
                textAlign: TextAlign.center,
                style: const TextStyle(color: Colors.grey, fontSize: 11, height: 1.3, letterSpacing: 1.0),
              ),
              const SizedBox(height: 32),

              // Campo para introduzir a Chave
              TextField(
                controller: _keyController,
                obscureText: _obscureText,
                style: const TextStyle(color: Colors.white),
                decoration: InputDecoration(
                  labelText: _local['enter_decryption_key_label'],
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
                      : Text(
                          _local['access_vault_button']!,
                          style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
                        ),
                ),
              ),
              const SizedBox(height: 36),

              // Texto Informativo do Rodapé (Formatado para telemóvel)
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 10.0),
                child: Text(
                  _local['footer_privacy_text']!,
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
  final Map<String, String> local;
  const VaultFilesGateScreen({super.key, required this.local});

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
        SnackBar(content: Text(widget.local['crypto_code_too_weak']!)),
      );
      return;
    }
    if (!firstTime && code.isEmpty) return;

    setState(() => _isProcessing = true);
    try {
      final salt = firstTime ? await VaultFilesKey.createSalt() : await VaultFilesKey.getSalt();
      if (salt == null) throw Exception(widget.local['vault_files_not_initialized']!);

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
          throw Exception(widget.local['invalid_vault_files_code']!);
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
        throw Exception(widget.local['vault_files_corrupted']!);
      }

      await VaultFilesStore.migratePending(filesBox);
      VaultFilesKey.markUnlocked();

      if (mounted) {
        Navigator.of(context).pushReplacement(
          MaterialPageRoute(builder: (context) => VaultFilesHomeScreen(local: widget.local)),
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
        title: Text((widget.local['secure_vault_files_short'] ?? 'Secure Vault Files').replaceAll('\n', ' '), style: const TextStyle(color: Colors.lightBlueAccent)),
        iconTheme: const IconThemeData(color: Colors.lightBlueAccent),
        elevation: 8,
        shadowColor: Colors.black,
        flexibleSpace: Container(
          decoration: const BoxDecoration(
            gradient: LinearGradient(
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
              colors: [Color(0xFF1e4d2b), Color(0xFF0a1a12)],
            ),
          ),
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
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(28.0),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Icon(Icons.folder_copy_rounded, color: Colors.lightBlueAccent, size: 60),
                const SizedBox(height: 20),
                Text(
                  firstTime ? widget.local['create_vault_files_code_title']! : widget.local['enter_vault_files_code_title']!,
                  textAlign: TextAlign.center,
                  style: const TextStyle(color: Colors.white, fontSize: 18, fontWeight: FontWeight.bold, letterSpacing: 1.2),
                ),
                const SizedBox(height: 10),
                Text(
                  firstTime
                      ? widget.local['vault_files_code_desc_create']!
                      : widget.local['vault_files_code_desc_enter']!,
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
                    labelText: firstTime ? widget.local['set_vault_files_code_label']! : widget.local['vault_files_code_label']!,
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
                        : Text(firstTime ? widget.local['create_vault_button']! : widget.local['unlock_button']!, style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
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
  final Map<String, String> local;
  const VaultFilesHomeScreen({super.key, required this.local});

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
      final msg = (widget.local['imported_skipped_toast'] ?? '{imported} imported, {skipped} skipped (max {mb}MB each).')
          .replaceAll('{imported}', '$imported')
          .replaceAll('{skipped}', '$skipped')
          .replaceAll('{mb}', '${kMaxVaultFileBytes ~/ (1024 * 1024)}');
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(msg)));
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
          title: Text(entry['fileName'] ?? widget.local['document_label']!, style: const TextStyle(color: Colors.white)),
          content: Text(
            (widget.local['document_stored_encrypted_desc'] ?? 'This document is stored encrypted in your Vault Files ({kb} KB). Use Export to save it back to your phone or share it.')
                .replaceAll('{kb}', (bytes.length / 1024).toStringAsFixed(1)),
            style: const TextStyle(color: Colors.white70),
          ),
          actions: [
            TextButton(onPressed: () => _exportEntry(entry, bytes), child: Text(widget.local['export_button']!, style: const TextStyle(color: Colors.greenAccent))),
            TextButton(onPressed: () => Navigator.pop(ctx), child: Text(widget.local['close_button']!, style: const TextStyle(color: Colors.lightBlueAccent))),
          ],
        ),
      );
    }
  }

  Future<void> _sendEntry(Map<String, dynamic> entry) async {
    final contactsStr = Hive.box('padlock_vault').get('contacts');
    final List contacts = contactsStr != null ? jsonDecode(contactsStr) : [];
    if (contacts.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(widget.local['no_contacts_yet']!)));
      return;
    }
    final selected = await showDialog<String>(
      context: context,
      builder: (ctx) => Dialog(
        backgroundColor: Colors.transparent,
        child: Container(
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(16),
            gradient: const LinearGradient(
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
              colors: [Color(0xFF1e4d2b), Color(0xFF0a1a12)],
            ),
            border: Border.all(color: Colors.greenAccent.withValues(alpha: 0.4)),
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(widget.local['send_to_title']!, style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 16)),
              const SizedBox(height: 12),
              SizedBox(
                width: double.maxFinite,
                child: ListView(
                  shrinkWrap: true,
                  children: contacts.map<Widget>((c) {
                    // O ID serve só para encaminhar a mensagem (ver
                    // sendEncryptedFile) - quem usa a app só vê o nome que
                    // deu ao contacto (renomear não muda o ID por baixo).
                    final routingId = (c['id'] ?? c['name']).toString();
                    final displayName = (c['name'] ?? c['id']).toString();
                    return Container(
                      margin: const EdgeInsets.only(bottom: 6),
                      decoration: BoxDecoration(
                        color: Colors.black.withValues(alpha: 0.25),
                        borderRadius: BorderRadius.circular(10),
                      ),
                      child: ListTile(
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                        title: Text(displayName, style: const TextStyle(color: Color(0xFFe4efe6), fontSize: 13, fontWeight: FontWeight.w600)),
                        trailing: const Icon(Icons.arrow_forward, color: Colors.greenAccent, size: 18),
                        onTap: () => Navigator.pop(ctx, routingId),
                      ),
                    );
                  }).toList(),
                ),
              ),
            ],
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
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(widget.local['sent_toast']!)));
    } catch (e) {
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('${widget.local['failed_to_send_prefix']}: $e')));
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
            ? '${widget.local['received_from_prefix']} $peer'
            : direction == 'sent'
                ? '${widget.local['sent_to_prefix']} $peer'
                : widget.local['stored_locally_not_sent']!;
        // Botões redondos com o mesmo verde transacional usado no resto da
        // app (em vez do cinzento quase preto de antes), e texto do
        // subtítulo em branco-pérola em vez de cinzento.
        Widget roundActionButton({required IconData icon, required Color iconColor, required VoidCallback onPressed}) {
          return Container(
            width: 36,
            height: 36,
            margin: const EdgeInsets.symmetric(horizontal: 2),
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              gradient: const LinearGradient(
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
                colors: [Color(0xFF1e4d2b), Color(0xFF0a1a12)],
              ),
              border: Border.all(color: Colors.greenAccent.withValues(alpha: 0.35)),
            ),
            child: IconButton(
              padding: EdgeInsets.zero,
              icon: Icon(icon, color: iconColor, size: 18),
              onPressed: onPressed,
            ),
          );
        }
        return Card(
          color: const Color(0xFF151515),
          margin: const EdgeInsets.only(bottom: 8),
          child: ListTile(
            leading: Icon(isPhoto ? Icons.image : Icons.description, color: Colors.lightBlueAccent),
            title: Text(entry['fileName'] ?? '', style: const TextStyle(color: Colors.white), overflow: TextOverflow.ellipsis),
            subtitle: Text(subtitle, style: const TextStyle(color: Color(0xFFe4efe6), fontSize: 11)),
            onTap: () => _viewEntry(entry),
            trailing: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                _sendingIds.contains(entry['id'].toString())
                    ? const SizedBox(width: 20, height: 20, child: Padding(padding: EdgeInsets.all(2), child: CircularProgressIndicator(strokeWidth: 2, color: Colors.greenAccent)))
                    : roundActionButton(icon: Icons.send, iconColor: Colors.greenAccent, onPressed: () => _sendEntry(entry)),
                roundActionButton(icon: Icons.delete, iconColor: Colors.redAccent, onPressed: () => _deleteEntry(entry)),
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
        title: Text((widget.local['secure_vault_files_short'] ?? 'Secure Vault Files').replaceAll('\n', ' '), style: const TextStyle(color: Colors.lightBlueAccent)),
        iconTheme: const IconThemeData(color: Colors.lightBlueAccent),
        elevation: 8,
        shadowColor: Colors.black,
        flexibleSpace: Container(
          decoration: const BoxDecoration(
            gradient: LinearGradient(
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
              colors: [Color(0xFF1e4d2b), Color(0xFF0a1a12)],
            ),
          ),
        ),
        actions: [
          IconButton(icon: const Icon(Icons.lock, color: Colors.lightBlueAccent), onPressed: _lockAndExit),
        ],
        bottom: TabBar(
          controller: _tabController,
          indicatorColor: Colors.lightBlueAccent,
          labelColor: Colors.lightBlueAccent,
          unselectedLabelColor: Colors.grey,
          tabs: [
            Tab(text: widget.local['tab_personal']!),
            Tab(text: widget.local['tab_received']!),
            Tab(text: widget.local['tab_sent']!),
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
            _buildList(_personalEntries, widget.local['personal_files_empty']!),
            _buildList(_receivedEntries, widget.local['received_files_empty']!),
            _buildList(_sentEntries, widget.local['sent_files_empty']!),
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
  final Map<String, String> local;
  const CryptoVaultGateScreen({super.key, required this.local});
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
        SnackBar(content: Text(widget.local['crypto_code_too_weak']!)),
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
          SnackBar(content: Text(widget.local['invalid_recovery_phrase']!)),
        );
        return;
      }
    }

    setState(() => _isProcessing = true);
    try {
      final salt = firstTime ? await CryptoWalletKey.createSalt() : await CryptoWalletKey.getSalt();
      if (salt == null) throw Exception(widget.local['crypto_vault_not_initialized']!);

      final derivedKey = await PadlockVaultKey.deriveKey(code, salt);

      // Nunca abrir o Hive com uma chave ainda não confirmada - mesma razão
      // dos outros dois cofres: pode não dar erro (só lixo válido-parecido),
      // e uma abertura falhada pode deixar a caixa presa a recusar até a
      // chave certa depois.
      if (!firstTime) {
        final validKey = await PadlockVaultKey.verifyKeyHash('padlock_crypto_vault_keyhash', derivedKey);
        if (!validKey) {
          throw Exception(widget.local['invalid_crypto_vault_code']!);
        }
      }

      if (Hive.isBoxOpen('padlock_crypto_vault')) {
        try { await Hive.box('padlock_crypto_vault').close(); } catch (_) {}
      }
      final walletBox = await Hive.openBox('padlock_crypto_vault', encryptionCipher: HiveAesCipher(derivedKey));

      // Segunda camada, dentro do próprio cofre.
      final canary = walletBox.get('_vault_canary');
      if (!firstTime && canary != 'padlock_ok') {
        throw Exception(widget.local['crypto_vault_corrupted']!);
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
              MaterialPageRoute(builder: (context) => MnemonicRevealScreen(sentence: mnemonic.sentence, local: widget.local)),
            );
          }
        }
      }

      if (mounted) {
        Navigator.of(context).pushReplacement(
          MaterialPageRoute(builder: (context) => CryptoVaultHomeScreen(local: widget.local)),
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
        title: Text((widget.local['secure_crypto_vault_short'] ?? 'Secure Crypto Vault').replaceAll('\n', ' '), style: const TextStyle(color: Colors.greenAccent)),
        iconTheme: const IconThemeData(color: Colors.greenAccent),
        elevation: 8,
        shadowColor: Colors.black,
        flexibleSpace: Container(
          decoration: const BoxDecoration(
            gradient: LinearGradient(
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
              colors: [Color(0xFF1e4d2b), Color(0xFF0a1a12)],
            ),
          ),
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
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(28.0),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                // Mesmo "tubo" com o diamante usado depois de entrar (ver
                // CryptoVaultHomeScreen) - antes disto era só o emoji solto,
                // sem o círculo/moldura a condizer com o resto da app.
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
                  child: const Center(child: Text('💎', style: TextStyle(fontSize: 40))),
                ),
                const SizedBox(height: 20),
                Text(
                  firstTime ? widget.local['create_crypto_vault_code_title']! : widget.local['enter_crypto_vault_code_title']!,
                  textAlign: TextAlign.center,
                  style: const TextStyle(color: Colors.white, fontSize: 18, fontWeight: FontWeight.bold, letterSpacing: 1.2),
                ),
                const SizedBox(height: 10),
                Text(
                  firstTime
                      ? widget.local['crypto_code_desc_create']!
                      : widget.local['crypto_code_desc_enter']!,
                  textAlign: TextAlign.center,
                  style: TextStyle(color: Colors.grey.shade400, fontSize: 12, height: 1.3),
                ),
                if (firstTime) ...[
                  const SizedBox(height: 8),
                  TextButton(
                    onPressed: () => setState(() => _restoreMode = !_restoreMode),
                    child: Text(
                      _restoreMode ? widget.local['create_new_wallet_instead']! : widget.local['already_have_recovery_phrase']!,
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
                      labelText: widget.local['recovery_phrase_label']!,
                      labelStyle: const TextStyle(color: Colors.grey),
                      hintText: widget.local['recovery_phrase_hint']!,
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
                    labelText: firstTime ? widget.local['set_crypto_vault_code_label']! : widget.local['crypto_vault_code_label']!,
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
                              firstTime ? (_restoreMode ? widget.local['restore_wallet_button']! : widget.local['create_wallet_button']!) : widget.local['unlock_button']!,
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
  final Map<String, String> local;
  const MnemonicRevealScreen({super.key, required this.sentence, required this.local});
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
          title: Text(widget.local['recovery_phrase_title']!, style: const TextStyle(color: Colors.greenAccent)),
          elevation: 8,
          shadowColor: Colors.black,
          flexibleSpace: Container(
            decoration: const BoxDecoration(
              gradient: LinearGradient(
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
                colors: [Color(0xFF1e4d2b), Color(0xFF0a1a12)],
              ),
            ),
          ),
        ),
        // Sem SafeArea, o botão CONTINUE e a checkbox ficavam por baixo da
        // barra de gestos/botões do Android em telemóveis sem botões físicos.
        body: SafeArea(
          child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            children: [
              Text(
                widget.local['recovery_phrase_warning']!,
                style: const TextStyle(color: Colors.redAccent, fontSize: 12, height: 1.4),
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
                title: Text(widget.local['recovery_phrase_confirm_checkbox']!, style: const TextStyle(color: Colors.white70, fontSize: 12)),
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
                    child: Text(widget.local['continue_button']!, style: const TextStyle(fontWeight: FontWeight.bold)),
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
  final Map<String, String> local;
  const CryptoVaultHomeScreen({super.key, required this.local});
  @override
  State<CryptoVaultHomeScreen> createState() => _CryptoVaultHomeScreenState();
}

class _CryptoVaultHomeScreenState extends State<CryptoVaultHomeScreen> {
  Timer? _sessionTimer;
  EthereumAddress? _address;
  EthPrivateKey? _credentials;
  // Uma entrada por moeda suportada: texto do saldo já formatado + cotação
  // USD (null enquanto não chegou/falhou), para mostrar "≈ $X.XX" por baixo.
  final Map<String, String> _balanceText = {};
  final Map<String, double?> _usdPrice = {for (final t in PadlockWallet.supportedTokens) t.symbol: null};
  bool _isRefreshing = false;

  @override
  void initState() {
    super.initState();
    for (final token in PadlockWallet.supportedTokens) {
      _balanceText[token.symbol] = widget.local['loading_text']!;
    }
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
        if (mounted) setState(() => _balanceText[token.symbol] = widget.local['could_not_load_balance']!);
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
        title: Text(widget.local['receive_dialog_title']!, style: const TextStyle(color: Colors.greenAccent)),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              padding: const EdgeInsets.all(12),
              color: Colors.white,
              child: QrImageView(data: _address!.hexEip55, size: 200),
            ),
            const SizedBox(height: 16),
            Text(widget.local['receive_address_warning']!, textAlign: TextAlign.center, style: const TextStyle(color: Colors.grey, fontSize: 10)),
            const SizedBox(height: 10),
            SelectableText(_address!.hexEip55, style: const TextStyle(color: Colors.white, fontSize: 11)),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () {
              Clipboard.setData(ClipboardData(text: _address!.hexEip55));
              ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(widget.local['address_copied_toast']!)));
            },
            child: Text(widget.local['copy_button']!.toUpperCase(), style: const TextStyle(color: Colors.lightBlueAccent)),
          ),
          TextButton(onPressed: () => Navigator.pop(ctx), child: Text(widget.local['close_button']!.toUpperCase(), style: const TextStyle(color: Colors.grey))),
        ],
      ),
    );
  }

  Future<void> _openSendScreen() async {
    if (_address == null || _credentials == null) return;
    final result = await Navigator.of(context).push<bool>(
      MaterialPageRoute(
        builder: (context) => CryptoSendScreen(credentials: _credentials!, fromAddress: _address!, local: widget.local),
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
        title: Text((widget.local['secure_crypto_vault_short'] ?? 'Secure Crypto Vault').replaceAll('\n', ' '), style: const TextStyle(color: Colors.greenAccent)),
        iconTheme: const IconThemeData(color: Colors.greenAccent),
        elevation: 8,
        shadowColor: Colors.black,
        flexibleSpace: Container(
          decoration: const BoxDecoration(
            gradient: LinearGradient(
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
              colors: [Color(0xFF1e4d2b), Color(0xFF0a1a12)],
            ),
          ),
        ),
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
                  child: Text(widget.local['testnet_warning']!, style: const TextStyle(color: Colors.redAccent, fontSize: 11, fontWeight: FontWeight.bold)),
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
                  // Mesmo diamante emoji usado no botão do Perfil e no resto
                  // da app - o ícone Icons.diamond do Material não tinha
                  // nada a ver com o resto do visual.
                  child: const Center(child: Text('💎', style: TextStyle(fontSize: 40))),
                ),
                const SizedBox(height: 20),
                Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Text(widget.local['balances_label']!, style: const TextStyle(color: Colors.grey, fontSize: 12)),
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
                            _balanceText[token.symbol] ?? widget.local['loading_text']!,
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
                          label: Text(widget.local['receive_button']!.toUpperCase()),
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
                          label: Text(widget.local['send_button']!.toUpperCase()),
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
  final Map<String, String> local;
  const CryptoSendScreen({super.key, required this.credentials, required this.fromAddress, required this.local});
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
            SnackBar(content: Text(widget.local['camera_permission_denied']!)),
          );
        }
        return;
      }
      bool scanned = false;
      await Navigator.push(
        context,
        MaterialPageRoute(
          builder: (context) => Scaffold(
            appBar: AppBar(title: Text(widget.local['scan_wallet_address_title']!)),
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
        SnackBar(content: Text(widget.local['invalid_wallet_address']!)),
      );
      return;
    }

    final typedValue = double.tryParse(amountText);
    if (typedValue == null || typedValue <= 0) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(widget.local['enter_valid_amount']!)),
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
          SnackBar(content: Text(widget.local['price_not_loaded']!)),
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
            title: Text(widget.local['transaction_sent_title']!, style: const TextStyle(color: Colors.greenAccent)),
            content: SelectableText(txHash, style: const TextStyle(color: Colors.white70, fontSize: 12)),
            actions: [
              TextButton(
                onPressed: () {
                  Navigator.pop(ctx);
                  Navigator.pop(context, true);
                },
                child: Text(widget.local['done_button']!.toUpperCase(), style: const TextStyle(color: Colors.lightBlueAccent)),
              ),
            ],
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('${widget.local['send_failed_prefix']}: $e')),
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
        title: Text(widget.local['send_title']!, style: const TextStyle(color: Colors.lightBlueAccent)),
        iconTheme: const IconThemeData(color: Colors.lightBlueAccent),
        elevation: 8,
        shadowColor: Colors.black,
        flexibleSpace: Container(
          decoration: const BoxDecoration(
            gradient: LinearGradient(
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
              colors: [Color(0xFF1e4d2b), Color(0xFF0a1a12)],
            ),
          ),
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
        child: SafeArea(
          child: Padding(
            padding: const EdgeInsets.all(20),
            child: Column(
              children: [
                Container(
                  padding: const EdgeInsets.symmetric(vertical: 6, horizontal: 12),
                  decoration: BoxDecoration(color: Colors.redAccent.withValues(alpha: 0.15), borderRadius: BorderRadius.circular(8)),
                  child: Text(widget.local['testnet_warning']!, style: const TextStyle(color: Colors.redAccent, fontSize: 11, fontWeight: FontWeight.bold)),
                ),
                const SizedBox(height: 24),
                TextField(
                  controller: _addressController,
                  style: const TextStyle(color: Colors.white, fontSize: 12),
                  decoration: InputDecoration(
                    labelText: widget.local['recipient_address_label']!,
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
                    labelText: widget.local['coin_label']!,
                    labelStyle: const TextStyle(color: Colors.grey),
                    // Sem isto, o rótulo "Coin" às vezes descia e ficava por
                    // cima do nome da moeda escolhida quando o ecrã
                    // redesenhava por outro motivo (ex: escrever no campo do
                    // montante) - agora fica sempre fixo em cima, nunca a
                    // sobrepor o texto.
                    floatingLabelBehavior: FloatingLabelBehavior.always,
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
                    Text(widget.local['amount_in_label']!, style: const TextStyle(color: Colors.grey, fontSize: 12)),
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
                    labelText: _amountInUsd ? widget.local['amount_usd_label']! : '${widget.local['amount_label_prefix']} (${_selectedToken.symbol})',
                    labelStyle: const TextStyle(color: Colors.grey),
                    enabledBorder: OutlineInputBorder(borderSide: const BorderSide(color: Colors.grey), borderRadius: BorderRadius.circular(8)),
                    focusedBorder: const OutlineInputBorder(borderSide: BorderSide(color: Colors.lightBlueAccent), borderRadius: BorderRadius.all(Radius.circular(8))),
                    helperText: _price == null
                        ? widget.local['loading_price']!
                        : (_conversionHint ?? '${widget.local['price_label_prefix']}: \$${_price!.toStringAsFixed(_price! < 1 ? 6 : 2)} / ${_selectedToken.symbol}'),
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
                          : Text(widget.local['confirm_send_button']!.toUpperCase(), style: const TextStyle(fontWeight: FontWeight.bold)),
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
    final padlock = context.findAncestorStateOfType<_PadlockAppState>();
    final lang = padlock?._currentLanguage ?? 'EN';
    final local = t[lang] ?? t['EN']!;
    Navigator.of(context).push(
      MaterialPageRoute(builder: (context) => CryptoVaultGateScreen(local: local)),
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
                final padlock = dialogContext.findAncestorStateOfType<_PadlockAppState>();
                final lang = padlock?._currentLanguage ?? 'EN';
                final local = t[lang] ?? t['EN']!;
                Navigator.of(dialogContext).push(
                  MaterialPageRoute(builder: (context) => CryptoVaultGateScreen(local: local)),
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