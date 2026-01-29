import 'dart:convert';
import 'dart:io';
import 'package:device_info_plus/device_info_plus.dart';
import 'package:crypto/crypto.dart';
import 'package:uuid/uuid.dart';
import 'package:logger/logger.dart';
import 'package:eco_guide_auth_app/src/secure_storage.dart';

var logger = Logger();

class DeviceUtils {
  static final SecureStorage _secureStorage = SecureStorage();
  static String? _cachedDeviceId;

  // Gets or generates a stable device ID and stores it securely.
  static Future<String> getOrCreateDeviceId() async {
    if (_cachedDeviceId != null) {
      return _cachedDeviceId!;
    }

    String? storedId = await _secureStorage.readDeviceId();
    if (storedId != null && storedId.isNotEmpty) {
      _cachedDeviceId = storedId;
      logger.d('Retrieved device ID from secure storage: $_cachedDeviceId');
      return _cachedDeviceId!;
    }

    // If not found, generate a new one
    String newId = await _generateUniqueDeviceId();
    await _secureStorage.saveDeviceId(newId);
    _cachedDeviceId = newId;
    logger.i('Generated and stored new device ID: $_cachedDeviceId');
    return _cachedDeviceId!;
  }

  // Generates a device ID based on stable device info or a UUID as a fallback.
  static Future<String> _generateUniqueDeviceId() async {
    final di = DeviceInfoPlugin();
    try {
      if (Platform.isAndroid) {
        AndroidDeviceInfo androidInfo = await di.androidInfo;
        final payload = jsonEncode({
          'brand': androidInfo.brand,
          'model': androidInfo.model,
          'id': androidInfo.id, // Build.ID is a good stable identifier
          'fingerprint': androidInfo.fingerprint,
        });
        return sha256.convert(utf8.encode(payload)).toString();
      } else if (Platform.isIOS) {
        IosDeviceInfo iosInfo = await di.iosInfo;
        final payload = jsonEncode({
          'systemName': iosInfo.systemName,
          'model': iosInfo.model,
          'identifierForVendor': iosInfo.identifierForVendor, // Stable ID for vendor
        });
        return sha256.convert(utf8.encode(payload)).toString();
      } else if (Platform.isWeb) {
        WebBrowserInfo webInfo = await di.webBrowserInfo;
        final payload = jsonEncode({
          'userAgent': webInfo.userAgent,
          'vendor': webInfo.vendor,
          'hardwareConcurrency': webInfo.hardwareConcurrency,
        });
        return sha256.convert(utf8.encode(payload)).toString();
      }
    } catch (e) {
      logger.e('Failed to get device info, falling back to UUID: $e');
    }
    // Fallback to UUID
    return const Uuid().v4();
  }

  // Generates a hash for device fingerprinting (e.g., combining user agent and other non-PII data)
  static String fingerprintHash(String userAgent, String additionalInfo) {
    final data = utf8.encode('$userAgent|$additionalInfo');
    return sha256.convert(data).toString();
  }

  // Placeholder for device attestation (e.g., SafetyNet/PlayIntegrity on Android, DeviceCheck on iOS)
  static Future<String?> performDeviceAttestation() async {
    logger.i('Performing device attestation (placeholder).');
    // In a real app, this would integrate with native modules for attestation.
    // e.g., using a package like 'play_integrity' or platform channels for iOS DeviceCheck.
    // For now, return a mock attestation string.
    return Future.value('mock_attestation_result_passed');
  }
}