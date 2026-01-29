import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:local_auth/local_auth.dart';
import 'package:logger/logger.dart';
import 'package:eco_guide_auth_app/src/otp_service.dart';
import 'package:eco_guide_auth_app/src/token_manager.dart';
import 'package:eco_guide_auth_app/src/secure_storage.dart';
import 'package:eco_guide_auth_app/src/consent_widget.dart';
import 'package:eco_guide_auth_app/src/auth_client.dart';
import 'package:eco_guide_auth_app/src/device_utils.dart'; // For client IP simulation

var logger = Logger();

class AuthFlowScreen extends StatefulWidget {
  final OtpService otpService;
  final TokenManager tokenManager;
  final SecureStorage secureStorage;

  const AuthFlowScreen({
    Key? key,
    required this.otpService,
    required this.tokenManager,
    required this.secureStorage,
  }) : super(key: key);

  @override
  State<AuthFlowScreen> createState() => _AuthFlowScreenState();
}

class _AuthFlowScreenState extends State<AuthFlowScreen> {
  final TextEditingController _identifierController = TextEditingController();
  final TextEditingController _otpController = TextEditingController();
  String _currentScreen = 'login'; // 'login', 'otp_entry', 'consent', 'home'
  String _message = '';
  String _currentUserId = '';

  @override
  void initState() {
    super.initState();
    _checkExistingSession();
  }

  Future<void> _checkExistingSession() async {
    try {
      await widget.tokenManager.ensureAccessToken();
      final userId = await widget.tokenManager.getUserId(); // Use getUserId from tokenManager
      if (widget.tokenManager.accessValid && userId != null) {
        setState(() {
          _currentUserId = userId;
          _currentScreen = 'home';
          _message = 'Welcome back!';
        });
      } else {
        _message = 'Please log in.';
      }
    } catch (e) {
      logger.i('No active session found or refresh failed: $e');
      _message = 'Session expired. Please log in.';
      setState(() { _currentScreen = 'login'; });
    }
  }

  // --- Login Flow ---
  Future<void> _requestOtp() async {
    setState(() { _message = ''; });
    final identifier = _identifierController.text.trim();
    if (identifier.isEmpty) {
      setState(() { _message = 'Please enter an identifier (email/phone).'; });
      return;
    }
    try {
      // Simulate getting client IP for device fingerprinting
      final clientIp = '192.168.1.1'; // In a real app, this would be from the network request or a service
      final resp = await widget.otpService.requestOtp(identifier, 'sms', clientIp);
      if (resp['status'] == 'ok') {
        setState(() {
          _message = 'OTP sent to $identifier. Please check your device.';
          _currentScreen = 'otp_entry';
        });
      } else if (resp.containsKey('retry_after_seconds')) {
        setState(() {
          _message = 'Too many requests. Try again after ${resp['retry_after_seconds']} seconds.';
        });
      }
    } on DioException catch (e) { // Catch Dio specific errors
      logger.e('OTP request Dio error: ${e.response?.data ?? e.message}');
      setState(() { _message = e.response?.data?['message'] ?? 'Failed to request OTP. Please try again.'; });
    } catch (e) {
      logger.e('OTP request failed: $e');
      setState(() { _message = 'Failed to request OTP. Please try again.'; });
    }
  }

  Future<void> _verifyOtp() async {
    setState(() { _message = ''; });
    final identifier = _identifierController.text.trim();
    final otp = _otpController.text.trim();
    if (otp.isEmpty) {
      setState(() { _message = 'Please enter the OTP.'; });
      return;
    }
    try {
      final resp = await widget.otpService.verifyOtp(identifier, otp);
      if (resp.containsKey('access_token')) {
        // OTP verified. Now check if consent is needed.
        // Assuming backend tells us if user is new or existing and needs consent.
        // For this example, we'll force a consent flow after successful OTP.
        setState(() {
          _message = 'OTP verified. Please review our Privacy Policy.';
          _currentScreen = 'consent';
        });
        // We'll save tokens after consent
        // Store these for later use if consent is successful
        _tempAccessToken = resp['access_token'];
        _tempExpiresIn = resp['expires_in'];
        _tempRefreshToken = resp['refresh_token'];
        _tempUserIdFromOtp = resp['user_id'];
      } else {
        setState(() { _message = 'Invalid OTP. Please try again.'; });
      }
    } on DioException catch (e) {
      logger.e('OTP verification Dio error: ${e.response?.data ?? e.message}');
      setState(() { _message = e.response?.data?['message'] ?? 'Failed to verify OTP. Please try again.'; });
    } catch (e) {
      logger.e('OTP verification failed: $e');
      setState(() { _message = 'Failed to verify OTP. Please try again.'; });
    }
  }

  // Temp storage for tokens between verifyOtp and handleConsent
  String? _tempAccessToken;
  int? _tempExpiresIn;
  String? _tempRefreshToken;
  String? _tempUserIdFromOtp;

  Future<void> _handleConsent(bool agreed) async {
    setState(() { _message = ''; });
    final tempUserIdForConsent = widget.otpService.getCurrentTempUserId(); // Use current tempUserId

    if (tempUserIdForConsent == null) {
      setState(() { _message = 'Consent flow error: no temporary user ID.'; _currentScreen = 'login'; });
      return;
    }

    try {
      final resp = await widget.authClient.submitConsent(tempUserIdForConsent, agreed);
      if (agreed && resp['status'] == 'user_created') {
        // Consent given. Now finalize tokens if OTP was successful
        if (_tempAccessToken != null && _tempRefreshToken != null && _tempUserIdFromOtp != null) {
          await widget.tokenManager.setTokens(
            accessToken: _tempAccessToken!,
            accessExpiresInSeconds: _tempExpiresIn!,
            refreshToken: _tempRefreshToken!,
            userId: _tempUserIdFromOtp!,
          );
          setState(() {
            _currentUserId = _tempUserIdFromOtp!;
            _message = 'Consent given. Welcome to the app!';
            _currentScreen = 'home';
          });
        } else {
          setState(() { _message = 'Consent given, but tokens missing. Please re-login.'; _currentScreen = 'login'; });
        }
      } else {
        // User declined or consent failed
        await widget.otpService.resetOtpFlow(); // Clear temp user ID
        await widget.tokenManager.clearAll();
        setState(() {
          _message = 'Consent declined. You must agree to use the app.';
          _currentScreen = 'login';
        });
      }
    } on DioException catch (e) {
      logger.e('Consent submission Dio error: ${e.response?.data ?? e.message}');
      setState(() { _message = e.response?.data?['message'] ?? 'Failed to process consent. Please try again.'; _currentScreen = 'login'; });
    } catch (e) {
      logger.e('Consent submission failed: $e');
      setState(() { _message = 'Failed to process consent. Please try again.'; _currentScreen = 'login'; });
    } finally {
      // Clear temp token storage regardless of consent outcome
      _tempAccessToken = null;
      _tempExpiresIn = null;
      _tempRefreshToken = null;
      _tempUserIdFromOtp = null;
      widget.otpService.resetOtpFlow(); // Ensure tempUserId is also cleared
    }
  }

  Future<void> _logout() async {
    setState(() { _message = ''; });
    try {
      final currentUserId = await widget.tokenManager.getUserId();
      if (currentUserId != null) {
         await widget.authClient.revokeToken(userId: currentUserId); // Global logout
      }
      await widget.tokenManager.clearAll();
      widget.otpService.resetOtpFlow();
      setState(() {
        _currentUserId = '';
        _message = 'Logged out successfully.';
        _currentScreen = 'login';
      });
    } on DioException catch (e) {
      logger.e('Logout Dio error: ${e.response?.data ?? e.message}');
      setState(() { _message = e.response?.data?['message'] ?? 'Failed to log out. Please try again.'; });
    } catch (e) {
      logger.e('Logout failed: $e');
      setState(() { _message = 'Failed to log out. Please try again.'; });
    }
  }

  Future<void> _refreshAccessTokenManually() async {
    setState(() { _message = ''; });
    try {
      await widget.tokenManager.ensureAccessToken();
      setState(() {
        _message = 'Access token refreshed successfully!';
      });
    } on Exception catch (e) { // tokenManager throws Exception
      logger.e('Manual token refresh failed: $e');
      setState(() { _message = 'Failed to refresh token: $e'; });
      if (e.toString().contains('NO_REFRESH_TOKEN')) {
        setState(() { _currentScreen = 'login'; }); // Go back to login if refresh token is gone
      }
    }
  }

  Future<void> _authenticateWithBiometrics() async {
    final LocalAuthentication auth = LocalAuthentication();
    bool canCheckBiometrics;
    List<BiometricType> availableBiometrics;

    try {
      canCheckBiometrics = await auth.canCheckBiometrics;
      if (!canCheckBiometrics) {
        setState(() { _message = 'Biometrics not available on this device.'; });
        return;
      }
      availableBiometrics = await auth.getAvailableBiometrics();
      if (availableBiometrics.isEmpty) {
        setState(() { _message = 'No biometrics enrolled.'; });
        return;
      }

      bool authenticated = await auth.authenticate(
        localizedReason: 'Authenticate to access your account',
        options: const AuthenticationOptions(
          stickyAuth: true,
          useErrorDialogs: true,
        ),
      );

      if (authenticated) {
        // Upon successful biometric authentication, you'd typically retrieve
        // the refresh token from secure storage and perform a silent refresh.
        await _refreshAccessTokenManually();
        setState(() { _message = 'Biometric authentication successful!'; });
      } else {
        setState(() { _message = 'Biometric authentication failed or cancelled.'; });
      }
    } on PlatformException catch (e) {
      logger.e('Biometric authentication error: $e');
      setState(() { _message = 'Biometric error: ${e.message}'; });
    }
  }


  @override
  Widget build(BuildContext context) {
    Widget currentContent;

    switch (_currentScreen) {
      case 'login':
        currentContent = _buildLoginScreen();
        break;
      case 'otp_entry':
        currentContent = _buildOtpEntryScreen();
        break;
      case 'consent':
        currentContent = _buildConsentScreen();
        break;
      case 'home':
        currentContent = _buildHomeScreen();
        break;
      default:
        currentContent = _buildLoginScreen();
    }

    return Scaffold(
      appBar: AppBar(title: const Text('ECO-GUIDE Auth System')),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          children: [
            if (_message.isNotEmpty)
              Padding(
                padding: const EdgeInsets.only(bottom: 16.0),
                child: Text(_message, style: const TextStyle(color: Colors.red)),
              ),
            Expanded(child: currentContent),
          ],
        ),
      ),
    );
  }

  Widget _buildLoginScreen() {
    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        TextField(
          controller: _identifierController,
          decoration: const InputDecoration(labelText: 'Email or Phone'),
        ),
        const SizedBox(height: 20),
        ElevatedButton(
          onPressed: _requestOtp,
          child: const Text('Request OTP'),
        ),
        const SizedBox(height: 20),
        ElevatedButton(
          onPressed: _authenticateWithBiometrics,
          child: const Text('Authenticate with Biometrics (if available)'),
        ),
      ],
    );
  }

  Widget _buildOtpEntryScreen() {
    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        Text('OTP sent to ${_identifierController.text}'),
        TextField(
          controller: _otpController,
          decoration: const InputDecoration(labelText: 'Enter OTP'),
          keyboardType: TextInputType.number,
        ),
        const SizedBox(height: 20),
        ElevatedButton(
          onPressed: _verifyOtp,
          child: const Text('Verify OTP'),
        ),
        TextButton(
          onPressed: () {
            widget.otpService.resetOtpFlow();
            setState(() { _currentScreen = 'login'; _message = 'OTP flow cancelled.'; });
          },
          child: const Text('Cancel'),
        ),
      ],
    );
  }

  Widget _buildConsentScreen() {
    return ConsentWidget(
      title: 'Privacy Policy and Terms of Service',
      textHtml: '''
        <h1>Privacy Policy</h1>
        <p>This is a placeholder for our extensive privacy policy and terms of service.
        Please scroll to the end to indicate your agreement.</p>
        <p>Your data will be used to provide you with the services you request, to improve our services,
        and for internal analytics. We adhere to GDPR and ISO27001 standards.</p>
        <p>We do not share your personal identifiable information with third parties without your explicit consent.</p>
        <p>By agreeing, you acknowledge that you have read and understood our policies.</p>
        <p>...</p>
        <p>... (Imagine a very long legal text here that requires scrolling)</p>
        <p>... (More legal text to ensure scrolling is mandatory)</p>
        <p>... (Final legal paragraph)</p>
        ''',
      onAgree: () => _handleConsent(true),
      onDecline: () => _handleConsent(false),
    );
  }

  Widget _buildHomeScreen() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Text('Welcome, User ID: $_currentUserId!'),
          const SizedBox(height: 20),
          ElevatedButton(
            onPressed: _refreshAccessTokenManually,
            child: const Text('Refresh Access Token Manually'),
          ),
          const SizedBox(height: 20),
          ElevatedButton(
            onPressed: _logout,
            style: ElevatedButton.styleFrom(backgroundColor: Colors.red),
            child: const Text('Logout'),
          ),
        ],
      ),
    );
  }
}