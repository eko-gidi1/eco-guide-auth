import 'package:flutter/material.dart';
import 'package:logger/logger.dart';
import 'package:eco_guide_auth_app/src/auth_client.dart';
import 'package:eco_guide_auth_app/src/secure_storage.dart';
import 'package:eco_guide_auth_app/src/token_manager.dart';
import 'package:eco_guide_auth_app/src/otp_service.dart';
import 'package:eco_guide_auth_app/src/env_config.dart';
import 'package:eco_guide_auth_app/src/example_usage.dart';
import 'package:eco_guide_auth_app/src/device_utils.dart'; // For initial deviceId generation

var logger = Logger();

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  EnvConfig.load(); // Load environment variables

  final authClient = AuthClient(EnvConfig.apiBaseUrl);
  final secureStorage = SecureStorage();
  final tokenManager = TokenManager(secureStorage, authClient);
  final otpService = OtpService(authClient);

  runApp(MyApp(
    authClient: authClient,
    secureStorage: secureStorage,
    tokenManager: tokenManager,
    otpService: otpService,
  ));
}

class MyApp extends StatelessWidget {
  final AuthClient authClient;
  final SecureStorage secureStorage;
  final TokenManager tokenManager;
  final OtpService otpService;

  const MyApp({
    Key? key,
    required this.authClient,
    required this.secureStorage,
    required this.tokenManager,
    required this.otpService,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'ECO-GUIDE Auth',
      theme: ThemeData(
        primarySwatch: Colors.green,
        visualDensity: VisualDensity.adaptivePlatformDensity,
      ),
      home: AuthFlowScreen( // Our example auth flow
        otpService: otpService,
        tokenManager: tokenManager,
        secureStorage: secureStorage,
      ),
    );
  }
}