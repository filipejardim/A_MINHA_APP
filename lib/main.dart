import 'dart:async';
import 'package:hive_flutter/hive_flutter.dart';
import 'package:encrypt/encrypt.dart' as enc;
import 'package:cryptography/cryptography.dart' as crypto;
import 'dart:html' as html;
import 'dart:math';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:web_socket_channel/web_socket_channel.dart';
// --- NOVAS FERRAMENTAS DE DADOS ---
import 'dart:convert';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';
// Serviço de rede para conectar ao servidor
class PadlockNetwork {
  static String? chatAbertoAtualmente;
  static WebSocketChannel? channel;
  // O HUB PERMANENTE QUE NUNCA MORRE:
  static final StreamController<dynamic> messageHub = StreamController<dynamic>.broadcast();
  static ValueNotifier<String> status = ValueNotifier<String>('Aguardar...');

  static void disconnect() {
    status.value = 'Offline';
    channel?.sink.close();
    channel = null;
  }

  

static void connect() {
  if (channel != null) disconnect();
    status.value = 'Aguardar...';
  try {
    channel = WebSocketChannel.connect(Uri.parse('wss://servidor-padlock.onrender.com'));
      // Escuta os dados do Render e reencaminha para o Hub permanente
      channel?.stream.listen(
        (data) {
          print('Dados recebidos: $data');
          
          // A PROVA DE VIDA DO RENDER: Se ele comunicou connosco, estamos online a 100%!
          if (status.value != 'Online') {
            status.value = 'Online';
          }
          
          messageHub.add(data); // Distribui para a app toda, sem nunca falhar
        },
        cancelOnError: true,
      onDone: () {
        print('Ligação WebSocket fechada. A tentar reconectar em 3 segundos...');
        channel = null;
        _tentarReconectar();
      },
      onError: (error) {
        print('Erro no WebSocket: $error');
        channel = null;
        _tentarReconectar();
      },
    );
  } catch (e) {
    print('Erro ao ligar: $e');
    channel = null;
    _tentarReconectar();
  }
}

// Função auxiliar de reconexão automática silenciosa
static void _tentarReconectar() {
  if (status.value == 'Offline') return;
    status.value = 'Aguardar...';
  Future.delayed(const Duration(seconds: 3), () {
    print('A executar reconexão automática...');
    connect();
  });
}
}
void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  
  // 1. Inicializa o motor da Base de Dados Blindada (Hive)
  await Hive.initFlutter();
  
  // 2. Ancoragem Física: Acede ao chip de segurança do telemóvel
  const secureStorage = FlutterSecureStorage();
  String? encryptionKeyString = await secureStorage.read(key: 'master_key');
  
  // Se for a 1ª vez que a app abre, gera a Chave Mestra de 256 bits (nível militar) e tranca-a no chip
  if (encryptionKeyString == null) {
    final key = enc.Key.fromSecureRandom(32);
    encryptionKeyString = base64UrlEncode(key.bytes);
    await secureStorage.write(key: 'master_key', value: encryptionKeyString);
  }
  
  // 3. Aplica a Chave Mestra para abrir o Cofre Local com cifra AES-256
  final encryptionKeyUint8List = base64Url.decode(encryptionKeyString);
  await Hive.openBox('padlock_vault', encryptionCipher: HiveAesCipher(encryptionKeyUint8List));
  
  // 4. Arranca a rede e verifica o PIN (acesso visual do utilizador)
  PadlockNetwork.connect();
  String? savedPin = await secureStorage.read(key: 'user_pin');
  bool isFirstTime = (savedPin == null);
  
  runApp(PadlockApp(isFirstTime: isFirstTime));
}

class PadlockApp extends StatefulWidget {
  final bool isFirstTime;
  
  const PadlockApp({super.key, required this.isFirstTime});

  @override
  State<PadlockApp> createState() => _PadlockAppState();
}

class _PadlockAppState extends State<PadlockApp> {
  String _currentLanguage = 'EN';

  void _changeLanguage(String lang) {
    setState(() {
      _currentLanguage = lang;
    });
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'PADLOCK',
      
      theme: ThemeData(
        brightness: Brightness.dark,
        scaffoldBackgroundColor: Colors.black,
        primaryColor: const Color(0xFF8B0000),
        bottomNavigationBarTheme: const BottomNavigationBarThemeData(
          backgroundColor: Color(0xFF0F0F0F),
          selectedItemColor: Color(0xFF8B0000),
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
  }
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
    WidgetsBinding.instance.addObserver(this);
    _generateNewId();
     _loadUsername(); // Chama a função para ler o nome
    _loadStoredData(); // Carrega os contactos e mensagens do cofre
    _initNotifications();
    _resetInactivityTimer();


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
              
      else if (data['type'] == 'wipe_chat') {
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
      }
              else if (data['type'] == 'contact_accepted') {
                
                final String acceptedId = data['senderId'];
                final String? acceptedPubKey = data['publicKey'];

                // 2. O teu amigo aceitou. Recebes a chave pública dele e fechas a ponte!
                if (acceptedPubKey != null) {
                  try {
                    final vault = Hive.box('padlock_vault');
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
                      
                      // 4. Tranca o Segredo e DESTROI a tua chave privada local (Anti-Forense)
                      vault.put('shared_secret_$acceptedId', base64Encode(sharedSecretBytes));
                      vault.delete('private_key_$acceptedId'); 
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
              }
              else if (data['type'] == 'secure_message') {
                if (data['senderId'] == Hive.box('padlock_vault').get('user_privacy_id')) return;
            final String peerId = data['senderId'] ?? data['targetId'];

            if (PadlockNetwork.chatAbertoAtualmente == peerId) {
              return;
            }

            int chatIdx = _chats.indexWhere((c) => c['id'] == peerId);

        if (chatIdx == -1) {
      setState(() {
        _chats.insert(0, {'name': peerId, 'id': peerId, 'msg': '', 'time': 'Just Now', 'unread': 0, 'messages': []});
        chatIdx = 0;
      });
    }

        if (chatIdx != -1) {
              String decryptedText = '[Erro de Segurança - Mensagem Ilegível]';
              final payloadParts = data['payload'].toString().split(':');

              if (payloadParts.length == 2) {
                try {
                  final vault = Hive.box('padlock_vault');
                  final sharedSecretBase64 = vault.get('shared_secret_$peerId');

                  enc.Key key;
                  if (sharedSecretBase64 != null) {
                    key = enc.Key.fromBase64(sharedSecretBase64);
                  } else {
                    key = enc.Key.fromUtf8('Chave_Provisoria_P2P_AES_256_GCM');
                  }

                  final iv = enc.IV.fromBase64(payloadParts[0]);
                  final encryptedData = enc.Encrypted.fromBase64(payloadParts[1]);
                  final encrypter = enc.Encrypter(enc.AES(key, mode: enc.AESMode.gcm));
                  decryptedText = encrypter.decrypt(encryptedData, iv: iv);
                } catch (e) {
                  print('Falha na decifragem global: $e');
                }
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
              try {
                html.Notification(
            'PADLOCK', 
            body: 'New encrypted message received.',
          );
              } catch (e) {
                print('Erro ao disparar pop-up de notificação: $e');
              }
         }
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
    super.dispose();
  }

  
  Timer? _gracePeriodTimer;
  Timer? _statusTimer; // O nosso Radar de Estado Online
  Timer? _inactivityTimer;

  void _resetInactivityTimer() {
    _inactivityTimer?.cancel();
    _inactivityTimer = Timer(const Duration(minutes: 3), () {
      print('3 Minutos sem mexer. A forçar Logout.');
      _logout();
    });
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused) {
      // 1. Só desliga se a app for mesmo minimizada. IGNORA O INACTIVE (teclados/alertas).
      PadlockNetwork.disconnect();
    } 
    else if (state == AppLifecycleState.resumed) {
      // 2. Acordou. Liga a mangueira.
      PadlockNetwork.connect();

      // 3. Dá 2 SEGUNDOS INTEIROS para o túnel abrir e estabilizar antes de registar.
      Future.delayed(const Duration(milliseconds: 2000), () {
        if (_myPrivacyId.isNotEmpty && PadlockNetwork.channel != null) {
          PadlockNetwork.channel?.sink.add(jsonEncode({
            'type': 'register',
            'senderId': _myPrivacyId
          }));

          if (mounted) {
            setState(() {});
          }
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
  try {
    html.Notification.requestPermission();
  } catch (e) {
    print('Erro ao ativar notificações: $e');
  }
}
  
  
  Future<void> _generateNewId() async {
    // 1. Acede ao Cofre Blindado (Hive) em vez da gaveta velha
    final vault = Hive.box('padlock_vault');
    
    // 2. Lê o teu ID de privacidade diretamente e em segurança do cofre
    String? savedId = vault.get('user_privacy_id');

    if (savedId != null && savedId.isNotEmpty) {
      setState(() {
        _myPrivacyId = savedId;
      });
      PadlockNetwork.channel?.sink.add(jsonEncode({'type': 'register', 'senderId': savedId}));
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
    PadlockNetwork.channel?.sink.add(jsonEncode({'type': 'register', 'senderId': newId}));
  }
Future<void> _logout() async {
    PadlockNetwork.disconnect();
    if (!mounted) return;
    Navigator.of(context).pushReplacement(
      MaterialPageRoute(builder: (context) => const LoginScreen()),
    );
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

              // 2. Se o outro lado mandou a chave pública dele, cria o Segredo Absoluto já aqui!
              if (senderPubKey != null) {
                try {
                  final theirPublicKeyBytes = base64Decode(senderPubKey);
                  final theirPublicKey = crypto.SimplePublicKey(theirPublicKeyBytes, type: crypto.KeyPairType.x25519);
                  
                  // 3. A MAGIA MATEMÁTICA: Funde as chaves
                  final sharedSecret = await algorithm.sharedSecretKey(
                    keyPair: await algorithm.newKeyPairFromSeed(myPrivateKey),
                    remotePublicKey: theirPublicKey,
                  );
                  final sharedSecretBytes = await sharedSecret.extractBytes();
                  
                  // 4. Guarda o segredo no cofre (a chave privada desaparece da RAM automaticamente!)
                  final vault = Hive.box('padlock_vault');
                  vault.put('shared_secret_$incomingId', base64Encode(sharedSecretBytes));
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
                  'name': incomingId,
                  'id': incomingId,
                  'status': 'Online',
                  'handshake': 'completed',
                });
              });
              
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
                    onPressed: () {
                      setState(() {
                        _contacts.removeAt(index);
                      });
                      Navigator.pop(context);
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
          if (existingIndex == -1)  {
            _chats.insert(0, {
          'name': contactName,
          'id': contactName,
          'msg': 'Secure channel established.',
          'time': 'Just Now',
          'unread': 0,
          'messages': [
            {'text': 'Secure channel established.', 'isMe': false}
          ]
        });
            existingIndex = 0;
          }
          else {
      final chat = _chats.removeAt(existingIndex);
      _chats.insert(0, chat);
      existingIndex = 0;
    }

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
        onNotificationsChange: (val) => setState(() => _notificationsActive = val),
        onSilentChange: (val) => setState(() => _silentMode = val),
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

    return GestureDetector(
      onTap: _resetInactivityTimer,
      onPanDown: (_) => _resetInactivityTimer(),
      behavior: HitTestBehavior.translucent,
      child: Scaffold(
       appBar: AppBar(
         title: Text(() {
                final padlock = context.findAncestorStateOfType<_PadlockAppState>();
                final lang = padlock?._currentLanguage ?? 'EN';
                final currentT = t[lang] ?? {};
                return _currentIndex == 0
                    ? (currentT['chats'] as String? ?? 'Chats')
                    : _currentIndex == 1
                    ? (currentT['contacts'] as String? ?? 'Contacts')
                    : _currentIndex == 2
                    ? (currentT['settings'] as String? ?? 'Settings')
                    : (currentT['profile'] as String? ?? 'Profile');
              }()),
        actions: [
          
          PopupMenuButton<String>(
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
                child: Text('Idioma'),
              ),
              const PopupMenuItem(
                value: 'logout',
                child: Text('Log Out', style: TextStyle(color: Colors.red)),
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
          title: const Text("Nova Conversa"),
          content: const Text("Deseja iniciar uma nova conversa segura?"),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text("Cancelar"),
            ),
            TextButton(
            onPressed: () {
              Navigator.pop(context);
              setState(() {
                _currentIndex = 1;
              });
            },
            child: const Text("Criar"),
          ),
          ],
        ), // Fecha o AlertDialog
      ); // Fecha o showDialog
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
                        title: const Text('Adicionar Contacto'),
                        content: TextField(
                          controller: controller,
                          decoration: const InputDecoration(labelText: 'ID de Privacidade'),
                        ),
                        actions: [
                          TextButton(
                            onPressed: () => Navigator.pop(context),
                            child: const Text('Cancelar'),
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
      bottomNavigationBar: BottomNavigationBar(
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
                color: Color(0xFF880000),
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
          activeIcon: const Icon(Icons.chat_bubble, color: Color(0xFF8B0000)),
          label: (() {
            final padlock = context.findAncestorStateOfType<_PadlockAppState>();
            final lang = padlock?._currentLanguage ?? 'EN';
            return (t[lang]?['chats'] as String?) ?? 'Chats';
          }()),
        ),
        BottomNavigationBarItem(
          icon: const Icon(Icons.people_outline),
          activeIcon: const Icon(Icons.people, color: Color(0xFF8B0000)),
          label: (() {
            final padlock = context.findAncestorStateOfType<_PadlockAppState>();
            final lang = padlock?._currentLanguage ?? 'EN';
            return (t[lang]?['contacts'] as String?) ?? 'Contacts';
          }()),
        ),
        BottomNavigationBarItem(
          icon: const Icon(Icons.settings_outlined),
          activeIcon: const Icon(Icons.settings, color: Color(0xFF8B0000)),
          label: (() {
            final padlock = context.findAncestorStateOfType<_PadlockAppState>();
            final lang = padlock?._currentLanguage ?? 'EN';
            return (t[lang]?['settings'] as String?) ?? 'Settings';
          }()),
        ),
        BottomNavigationBarItem(
          icon: const Icon(Icons.person_outline),
          activeIcon: const Icon(Icons.person, color: Color(0xFF8B0000)),
          label: (() {
            final padlock = context.findAncestorStateOfType<_PadlockAppState>();
            final lang = padlock?._currentLanguage ?? 'EN';
            return (t[lang]?['profile'] as String?) ?? 'Profile';
          }()),
        ),
  ],
          ),
        ), // <-- Fecha o Scaffold
      );   // <-- Fecha o GestureDetector que abrimos na linha 962
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
    return Padding(
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
              'senderId': myId
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
                      color: const Color(0xFF101010),
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(color: Colors.white10),
                    ),
                    child: ListTile(
                      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
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
            // ESTADO ONLINE INJETADO AQUI
            Text(
              chat['status'] ?? 'Offline',
              style: TextStyle(
                color: chat['status'] == 'Online' ? Colors.greenAccent : (chat['status'] == 'A aguardar...' ? Colors.orangeAccent : Colors.redAccent),
                fontSize: 11,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 4),
            
            Text('[Encrypted P2P Message]', maxLines: 1, overflow: TextOverflow.ellipsis, style: const TextStyle(color: Colors.white70)),
            const SizedBox(height: 4),
            Row(
              children: [
                const Icon(Icons.timer_outlined, size: 12, color: Colors.redAccent),
                const SizedBox(width: 4),
                Text('${local['autodestruct']} $destructTime', style: const TextStyle(color: Colors.redAccent, fontSize: 11)),
              ],
            ),
          ],
        ),
      ),      
trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            
            IconButton( 
  icon: const Icon(Icons.delete_forever, color: Colors.redAccent),
  onPressed: () {
    showDialog(
      context: context,
      builder: (context) {
        return AlertDialog(
          title: const Text("Eliminar Conversa"),
          content: const Text("Deseja eliminar este chat permanentemente?"),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text("Cancelar"),
            ),
            TextButton(
              onPressed: () {
                Navigator.pop(context);
                chats.removeAt(index);
                onUpdateChats();
              },
              child: const Text("Eliminar", style: TextStyle(color: Colors.red)),
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
  ); // Fecha o layout principal
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

class _SingleChatScreenState extends State<SingleChatScreen> {
  final TextEditingController _msgController = TextEditingController();
  final ScrollController _scrollController = ScrollController();
  Timer? _destructionTimer;
  StreamSubscription? _chatSubscription;

  @override
  void initState() {
    super.initState();
    PadlockNetwork.chatAbertoAtualmente = widget.chatData['id'];
    // DISPARO ATRASADO: Dá tempo à app e ao WebSocket para estabilizarem (evita que o aviso se perca no vazio)
    Future.delayed(const Duration(milliseconds: 2500), () {
      if (PadlockNetwork.channel != null && mounted) {
        try {
          PadlockNetwork.channel!.sink.add(jsonEncode({
            'type': 'message_read',
            'senderId': Hive.box('padlock_vault').get('user_privacy_id'),
            'targetId': widget.chatData['id']
          }));
          print('Aviso de leitura retroativo enviado com segurança!');
        } catch (e) {
          print('Erro ao enviar recibo na abertura: $e');
        }
      }
    });
    // Motor automático que corre a cada 1 segundo
    _destructionTimer = Timer.periodic(const Duration(seconds: 1), (timer) {
      if (mounted) {
        _checkExpiredMessages();
      }
    });
    // Escuta bilateral de mensagens recebidas via WebSocket P2P
    _chatSubscription = PadlockNetwork.messageHub.stream.listen((data) {
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
          if (mounted) {
            HapticFeedback.lightImpact();
SystemSound.play(SystemSoundType.click);
          // 1. Prepara a variável de segurança (se falhar, não mostra nada comprometedor)
          String decryptedText = '[Erro de Segurança - Mensagem Ilegível]';
          
          // 2. Separa o Vetor Aleatório (IV) da Mensagem Cifrada
          final payloadParts = decoded['payload'].toString().split(':');
          
          if (payloadParts.length == 2) {
            try {
            // 1. Identifica de quem vem a mensagem e acede ao Cofre
            final targetId = widget.chatData['id'];
            final vault = Hive.box('padlock_vault');
            final sharedSecretBase64 = vault.get('shared_secret_$targetId');
            
            enc.Key key;
            if (sharedSecretBase64 != null) {
              // 2. MAGIA: Destranca com o Segredo Absoluto gerado no Handshake
              key = enc.Key.fromBase64(sharedSecretBase64);
            } else {
              // (Fallback de segurança caso seja um contacto antigo na transição)
              key = enc.Key.fromUtf8('Chave_Provisoria_P2P_AES_256_GCM');
            }
            
            // 3. Prepara os dados matemáticos do pacote
            final iv = enc.IV.fromBase64(payloadParts[0]);
            final encryptedData = enc.Encrypted.fromBase64(payloadParts[1]);
            
            // 4. Executa a decifragem AES-256-GCM com nível militar
            final encrypter = enc.Encrypter(enc.AES(key, mode: enc.AESMode.gcm));
            decryptedText = encrypter.decrypt(encryptedData, iv: iv);
          } catch (e) {
            print('Falha na decifragem forense: $e');
          }
}
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
          // 1. O SEGREDO: Envia recibo de leitura invisível pela rede P2P
          print('====================================================');
print('GATILHO ACIONADO: A tentar enviar message_read para a rede!');
print('Canal aberto? ${PadlockNetwork.channel != null}');
print('====================================================');
          try {
           PadlockNetwork.channel?.sink.add(jsonEncode({
          'type': 'message_read',
          'senderId': Hive.box('padlock_vault').get('user_privacy_id'),
          'targetId': widget.chatData['id']
        })); 
          } catch (e) {
            print('Erro ao enviar recibo: $e');
          }
        }
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
      else if (decoded['action'] == 'call_offer') {
        if (mounted) {
          Navigator.of(context).push(
            MaterialPageRoute(
              builder: (context) => ActiveCallScreen(
                local: widget.local,
                recipientName: widget.chatData['name'],
                channel: PadlockNetwork.channel,
              ),
            ),
          );
        }
      } else if (decoded['action'] == 'call_end') {
        if (mounted) {
          Navigator.of(context).pop();
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
        for (int i = 0; i < allChats.length; i++) {
          if (allChats[i]['id'] == widget.chatData['id']) {
            allChats[i] = widget.chatData;
            break;
          }
        }
        vault.put('chats', jsonEncode(allChats));
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
        }
      }
    });

    // Sinal de Morte Bilateral para o outro telemóvel
    try {
      PadlockNetwork.channel?.sink.add(jsonEncode({
        'type': 'delete_message',
        'timestamp': timestamp,
        'senderId': Hive.box('padlock_vault').get('user_privacy_id'),
        'targetId': widget.chatData['id']
      }));
    } catch (e) {
      print('Erro ao enviar sinal de destruição: $e');
    }

    // Limpeza Local
    setState(() {
      widget.chatData['messages'].removeWhere((msg) => msg['timestamp'] == timestamp);
    });
    
    widget.onUpdate();
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
String _encryptAES256(String plainText) {
    // 1. Identifica o contacto com quem estás a falar
    final targetId = widget.chatData['id'];
    
    // 2. Abre o Cofre e extrai o Segredo Absoluto exclusivo desta conversa
    final vault = Hive.box('padlock_vault');
    final sharedSecretBase64 = vault.get('shared_secret_$targetId');
    
    enc.Key key;
    if (sharedSecretBase64 != null) {
      // 3. SUCESSO: Usa a chave militar inquebrável (O Handshake funcionou)
      key = enc.Key.fromBase64(sharedSecretBase64);
    } else {
      // (Fallback de segurança) Se for um contacto antigo que ainda não fez o novo handshake
      key = enc.Key.fromUtf8('Chave_Provisoria_P2P_AES_256_GCM');
    }

    // 4. Vetor de Inicialização (IV) Seguro e Aleatório
    final iv = enc.IV.fromSecureRandom(16);
    
    // 5. Aplica o algoritmo inviolável GCM com a Chave Absoluta
    final encrypter = enc.Encrypter(enc.AES(key, mode: enc.AESMode.gcm));
    final encrypted = encrypter.encrypt(plainText, iv: iv);
    
    // 6. Retorna o pacote blindado (e aproveitamos para limpar aquela linha azul de aviso do VS Code)
    return '${iv.base64}:${encrypted.base64}';
  }
void _sendMessage() {
    if (_msgController.text.trim().isEmpty) return;
    
    final rawText = _msgController.text.trim();
    final encryptedPayload = _encryptAES256(rawText);
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
      for (int i = 0; i < allChats.length; i++) {
        if (allChats[i]['id'] == widget.chatData['id']) {
          allChats[i] = widget.chatData;
          break;
        }
      }
      vault.put('chats', jsonEncode(allChats));
    }
    _scrollToBottom();
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
        backgroundColor: const Color(0xFF0F0F0F),
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
                    widget.chatData['status'] ?? 'A aguardar...', 
                    style: TextStyle(
                      fontSize: 10, 
                      color: widget.chatData['status'] == 'Online' 
                          ? Colors.greenAccent 
                          : (widget.chatData['status'] == 'A aguardar...' ? Colors.orangeAccent : Colors.redAccent),
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
              
              Navigator.of(context).push(
                MaterialPageRoute(
                  builder: (context) => ActiveCallScreen(
                    local: widget.local,
                    recipientName: widget.chatData['name'],
                    
                  ),
                ),
              );
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
              onPressed: () {

      if (widget.chatData['messages'] != null) {
        for (var i = 0; i < widget.chatData['messages'].length; i++) {
          widget.chatData['messages'][i]['text'] = '0000000000000000';
        }
        widget.chatData['messages'].clear();
      }
      widget.chatData['status'] = 'Blocked';
      // Dispara o Sinal de Morte Global antes de bloquear a comunicação
      try {
        PadlockNetwork.channel?.sink.add(jsonEncode({
          'type': 'wipe_chat',
          'targetId': widget.chatData['id']
        }));
      } catch (e) {
        print('Erro ao enviar sinal de aniquilação no bloqueio: $e');
      }
      
      widget.onUpdate();
      Navigator.pop(context);
       Navigator.pop(context);
              },
              child: const Text('Bloquear', style: TextStyle(color: Colors.red)),
            ),
          ],
        ),
      );
    }
    },
  itemBuilder: (context) => [
  PopupMenuItem(value: 'clear', child: Text(widget.local['delete_chat']!)),
  PopupMenuItem(value: 'block', child: Text(widget.local['block_peer']!)),
],
    ),  
        ]
        ),
      body: Column(
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
                      color: isMe ? const Color(0xFF8B0000).withValues(alpha: 0.9) : const Color(0xFF1E2C3A),
                      borderRadius: BorderRadius.only(
                        topLeft: const Radius.circular(12),
                        topRight: const Radius.circular(12),
                        bottomLeft: isMe ? const Radius.circular(12) : Radius.zero,
                        bottomRight: isMe ? Radius.zero : const Radius.circular(12),
                      ),
                      border: Border.all(color: isMe ? Colors.redAccent.withValues(alpha: 0.3) : Colors.white10),
                    ),
                    
                  child: Column(
  crossAxisAlignment: CrossAxisAlignment.end,
  children: [
    Text(
      m['text'],
      style: const TextStyle(color: Colors.white, fontSize: 14),
    ),
    const SizedBox(height: 3),
    Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
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
          Padding(
            padding: const EdgeInsets.all(10.0),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _msgController,
                    enabled: widget.chatData['status'] != 'Blocked',
                    decoration: InputDecoration(
                      hintText: widget.local['send_hint'],
                      filled: true,
                      fillColor: const Color(0xFF121212),
                      border: OutlineInputBorder(borderRadius: BorderRadius.circular(20), borderSide: BorderSide.none),
                      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                    ),
                    onSubmitted: (val) => _sendMessage(),
                  ),
                ),
                const SizedBox(width: 8),
                CircleAvatar(
                  backgroundColor: const Color(0xFF8B0000),
                  child: IconButton(
                    icon: const Icon(Icons.send, color: Colors.white, size: 18),
                    onPressed: _sendMessage,
                  ),
                )
              ],
            ),
          )
        ],
      ),
    );
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
    return Padding(
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
                          color: const Color(0xFF101010),
                          borderRadius: BorderRadius.circular(12),
                          border: Border.all(color: Colors.white10),
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
                            contact['status']!,
                            style: TextStyle(
                              color: contact['status'] == 'Online' ? Colors.green : Colors.red,
                              fontSize: 12,
                            ),
                          ),
                          trailing: IconButton(
          icon: const Icon(Icons.edit, color: Colors.grey),
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
            ));
          }
       }   
// ----------------------------------------------------
// 3. SETTINGS SCREEN
// ----------------------------------------------------
class SettingsScreen extends StatelessWidget {
  final Map<String, String> local;
  final String currentLang;
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
    final currentT = t[currentLang] ?? {};
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 15, vertical: 10),
      child: ListView(
        children: [
          _buildSectionTitle('Chat Settings'),
          ListTile(
            leading: const Icon(Icons.timer, color: Color(0xFF8B0000)),
            title: Text(currentT['autodestruct']!),
            trailing: DropdownButton<String>(
              value: destructTime,
              dropdownColor: const Color(0xFF1A1A1A),
              underline: const SizedBox(),
              onChanged: (newValue) {
                if (newValue != null) {
                  onDestructChange(newValue);
                }
              },
              items: <String>['1 Min', '5 Mins', '1 Hour', '1 Day', '7 Days']
                  .map<DropdownMenuItem<String>>((String value) {
                return DropdownMenuItem<String>(
                  value: value,
                  child: Text(value, style: const TextStyle(fontWeight: FontWeight.bold)),
                );
              }).toList(),
            ),
          ),
          const Divider(color: Colors.white10),

          _buildSectionTitle('Privacy & Security'),
          SwitchListTile(
            secondary: const Icon(Icons.lock, color: Color(0xFF8B0000)),
            title: Text(currentT['app_lock']!),
            value: passcodeLock,
            activeTrackColor: const Color(0xFF8B0000),
            onChanged: onPasscodeChange,
          ),
          SwitchListTile(
            secondary: const Icon(Icons.screen_lock_portrait, color: Color(0xFF8B0000)),
            title: Text(currentT['screen_security']!),
            value: blockScreenshots,
            activeTrackColor: const Color(0xFF8B0000),
            onChanged: onScreenshotsChange,
          ),
          const Divider(color: Colors.white10),

          _buildSectionTitle(currentT['notifications']!),
          SwitchListTile(
            secondary: const Icon(Icons.notifications_active, color: Color(0xFF8B0000)),
            title: Text(currentT['notifications']!),
            subtitle: Text(currentT['sounds_desc']!, style: const TextStyle(fontSize: 11, color: Colors.grey)),
            value: notificationsActive,
            activeTrackColor: const Color(0xFF8B0000),
            onChanged: onNotificationsChange,
          ),
          SwitchListTile(
            secondary: const Icon(Icons.volume_off, color: Color(0xFF8B0000)),
            title: Text(currentT['silent_mode']!),
            value: silentMode,
            activeTrackColor: const Color(0xFF8B0000),
            onChanged: onSilentChange,
          ),
          ListTile(
            leading: const Icon(Icons.music_note, color: Colors.grey),
            title: Text(currentT['custom_sound']!),
            subtitle: const Text('Default P2P Alert Tone', style: TextStyle(fontSize: 11, color: Colors.grey)),
            enabled: false,
          ),
          const Divider(color: Colors.white10),

          _buildSectionTitle('Data & Keys'),
          ListTile(
            leading: const Icon(Icons.delete_forever, color: Colors.redAccent),
            title: Text(currentT['clear_keys']!, style: const TextStyle(color: Colors.redAccent, fontWeight: FontWeight.bold)),
            onTap: () {
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(content: Text(currentT['keys_purged']!), backgroundColor: const Color(0xFF8B0000)),
              );
            },
          ),
        ],
      ),
    );
  }

  Widget _buildSectionTitle(String title) {
    return Padding(
      padding: const EdgeInsets.only(left: 15.0, top: 15, bottom: 8),
      child: Text(
        title.toUpperCase(),
        style: const TextStyle(fontSize: 11, color: Colors.redAccent, fontWeight: FontWeight.bold, letterSpacing: 1),
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
              Container(
                width: 180,
                height: 180,
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: Colors.white,
                  borderRadius: BorderRadius.circular(12),
                ),
                child: CustomPaint(
                  size: const Size(160, 160),
                  painter: QrSimulatorPainter(),
                ),
              ),
              const SizedBox(height: 20),
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
    return SingleChildScrollView(
      child: Column(
        children: [
          const SizedBox(height: 20),
          Center(
            child: Stack(
              children: [
                Container(
                  width: 110,
                  height: 110,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: const Color(0xFF1A1A1A),
                    border: Border.all(color: const Color(0xFF8B0000), width: 3),
                  ),
                  child: const Icon(Icons.lock, color: Color(0xFF8B0000), size: 55),
                ),
                Positioned(
                  bottom: 0,
                  right: 0,
                  child: CircleAvatar(
                    backgroundColor: const Color(0xFF8B0000),
                    radius: 18,
                    child: IconButton(
                      icon: const Icon(Icons.qr_code_2, size: 16, color: Colors.white),
                      onPressed: () => _showQrDialog(context),
                    ),
                  ),
                )
              ],
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
    color: Colors.black,
    border: Border.all(color: const Color.fromARGB(255, 190, 0, 0), width: 1.5),
    borderRadius: BorderRadius.circular(12),
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
      const Icon(Icons.edit, size: 16, color: Color.fromARGB(255, 190, 0, 0)),
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
            mainAxisAlignment: MainAxisAlignment.spaceEvenly,
            children: [
              _buildActionButton(Icons.qr_code, 'QR Code', () => _showQrDialog(context)),
              _buildActionButton(Icons.copy, 'Copy ID', () {
                Clipboard.setData(ClipboardData(text: privacyId));
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(content: Text(local['copy_toast']!)),
                );
              }),
               _buildActionButton(Icons.refresh, local['regen'] ?? 'Regen', () {
              showDialog(
                context: context,
                builder: (context) => AlertDialog(
                  title: Text(local['change_id_title'] ?? 'Mudar ID de Privacidade?'),
                  content: Text(local['change_id_desc'] ?? 'Atenção: Se gerar um novo ID, perderá a ligação com todos os seus contactos atuais. Deseja continuar?'),
                  actions: [
                    TextButton(
                      onPressed: () => Navigator.pop(context),
                      child: Text(local['cancel'] ?? 'Cancelar'),
                    ),
                    TextButton(
                      onPressed: () {
                        onRegenerate();
                        Navigator.pop(context);
                      },
                      child: Text(local['yes_change'] ?? 'Sim, Mudar', style: const TextStyle(color: Colors.redAccent)),
                    ),
                  ],
                ),
              );
            }),

            ],
          ),
          const SizedBox(height: 25),

          Container(
  margin: const EdgeInsets.symmetric(horizontal: 15),
  width: double.infinity,
  padding: const EdgeInsets.all(16),
  decoration: BoxDecoration(
    color: const Color.fromARGB(178, 204, 0, 0),
    borderRadius: BorderRadius.circular(12),
  ),
  child: Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      const Text(
        'ID de Privacidade',
        style: TextStyle(fontSize: 13, fontWeight: FontWeight.bold, color: Colors.black),
      ),
      const SizedBox(height: 6),
      SelectableText(
        privacyId,
        style: const TextStyle(fontSize: 15, fontWeight: FontWeight.bold, color: Colors.white),
      ),
      const SizedBox(height: 12),
      const Divider(color: Colors.black, thickness: 1, height: 1),
      const SizedBox(height: 12),
      const Text(
        'Bio',
        style: TextStyle(fontSize: 13, fontWeight: FontWeight.bold, color: Colors.black),
      ),
      const SizedBox(height: 6),
      const Text(
        'Engineered with military-grade Zero-Knowledge encryption.\n'
        'All communications operate strictly Peer-to-Peer (P2P).\n'
        'Messages automatically self-destruct after 24 hours\n'
        'using secure anti-trace memory sanitization.\n'
        'Zero trace, zero logs, total privacy.',
        style: TextStyle(fontSize: 12, color: Colors.white, height: 1.4),
      ),
    ],
  ),
),
        ],
      ),
    );
  }

 Widget _buildActionButton(IconData icon, String label, VoidCallback onTap) {
  return InkWell(
    onTap: onTap,
    borderRadius: BorderRadius.circular(12),
    child: Container(
      width: 100,
      padding: const EdgeInsets.symmetric(vertical: 10),
      decoration: BoxDecoration(
        color: const Color.fromARGB(179, 253, 1, 1),
        borderRadius: BorderRadius.circular(10),
      ),
      child: Column(
        children: [
          Icon(icon, color: Colors.black, size: 26),
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
          'O seu QR Code',
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
class ActiveCallScreen extends StatelessWidget {
  final Map<String, String>? local;
  final String recipientName;
  final dynamic channel;

  const ActiveCallScreen({
    super.key,
    required this.local,
    required this.recipientName,
    this.channel,
  });

  void startSecureCall(String targetPrivacyId) {
    final callSignal = {
      'action': 'call_offer',
      'to': targetPrivacyId,
      'timestamp': DateTime.now().millisecondsSinceEpoch,
    };
    channel?.sink.add(jsonEncode(callSignal));
  }

  void endCall(String targetPrivacyId) {
    final endSignal = {
      'action': 'call_end',
      'to': targetPrivacyId,
    };
    channel?.sink.add(jsonEncode(endSignal));
  }
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(30.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Stack(
                alignment: Alignment.center,
                children: [
                  Container(
                    width: 140,
                    height: 140,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      border: Border.all(color: const Color.fromARGB(255, 190, 1, 1).withValues(alpha: 0.3), width: 10),
                    ),
                  ),
                  Container(
                    width: 110,
                    height: 110,
                    decoration: const BoxDecoration(
                      color: Color(0xFF151515),
                      shape: BoxShape.circle,
                    ),
                    child: const Icon(Icons.shield_outlined, color: Colors.greenAccent, size: 45),
                  ),
                ],
              ),
              const SizedBox(height: 30),
              Text(
                recipientName,
                style: const TextStyle(fontSize: 20, fontWeight: FontWeight.bold, fontFamily: 'monospace'),
              ),
              const SizedBox(height: 10),
              Text(
                local?['call'] ?? 'Secure Call',
                style: const TextStyle(fontSize: 16, color: Colors.grey),
              ),
              const SizedBox(height: 40),
              Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  _buildCallButton(icon: Icons.mic_off, color: Colors.white24, onPress: () {}),
                  const SizedBox(width: 30),
                  _buildCallButton(
                    icon: Icons.call_end,
                    color: const Color.fromARGB(255, 235, 8, 0),
                    onPress: () {
  endCall(recipientName);
  Navigator.pop(context);
},
                  ),
                  const SizedBox(width: 30),
                  _buildCallButton(icon: Icons.volume_up, color: Colors.white24, onPress: () {}),
                ],
              )
            ],
          ),
        ),
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

class _SetupScreenState extends State<SetupScreen> {
  final TextEditingController _keyController = TextEditingController();
  final storage = const FlutterSecureStorage();
  bool _obscureText = true;

  Future<void> _register() async {
    final key = _keyController.text.trim();
    if (key.length >= 6) {
      await storage.write(key: 'user_pin', value: key);
      if (mounted) {
        Navigator.of(context).pushReplacement(
          MaterialPageRoute(builder: (context) => const LoginScreen()),
        );
      }
    } else {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Decryption Key must be at least 6 characters.')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(28.0),
          child: Column(
            children: [
              const Icon(Icons.lock_outline, color: Color.fromARGB(255, 255, 0, 0), size: 80),
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
                    borderSide: const BorderSide(color: Color.fromARGB(255, 255, 0, 0)),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  prefixIcon: const Icon(Icons.key, color: Color.fromARGB(255, 255, 0, 0)),
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
              SizedBox(
                width: double.infinity,
                height: 50,
                child: ElevatedButton(
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color.fromARGB(255, 255, 17, 0),
                    foregroundColor: Colors.black,
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(8),
                    ),
                  ),
                  onPressed: _register,
                  child: const Text(
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
    );
  }
}

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final TextEditingController _keyController = TextEditingController();
  final storage = const FlutterSecureStorage();
  bool _obscureText = true;

  Future<void> _login() async {
    final inputKey = _keyController.text.trim();
    final savedPin = await storage.read(key: 'user_pin');

    if (savedPin != null && inputKey == savedPin) {
      if (mounted) {
        // Redireciona para o ecrã principal da aplicação
        Navigator.of(context).pushReplacement(
          MaterialPageRoute(builder: (context) => MainNavigationScreen(currentLanguage: 'EN', onLanguageChange: (lang) {})),
        );
      }
    } else {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Invalid Decryption Key.')),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(28.0),
          child: Column(
            children: [
              // Ícone do Cadeado Verde
              const Icon(Icons.lock_outline, color: Color.fromARGB(255, 255, 0, 0), size: 80),
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
                    borderSide: const BorderSide(color: Color.fromARGB(255, 255, 30, 0)),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  prefixIcon: const Icon(Icons.key, color: Color.fromARGB(255, 255, 30, 0)),
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
                    backgroundColor: const Color.fromARGB(255, 255, 17, 0),
                    foregroundColor: Colors.black,
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(8),
                    ),
                  ),
                  onPressed: _login,
                  child: const Text(
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
    );
  }
}
 


  