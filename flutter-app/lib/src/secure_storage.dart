import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:logger/logger.dart';

var logger = Logger();

class SecureStorage {
  final FlutterSecureStorage _storage = const FlutterSecureStorage();

  // Keys for secure storage
  static const _keyRefresh = 'refresh_token';
  static const _keyDeviceId = 'device_id';
  static const _keyPinHash = 'local_pin_hash'; // For local biometric/PIN protection
  static const _keyUserId = 'user_id'; // Storing current user_id securely

  Future<void> saveRefreshToken(String token) async {
    logger.d('Saving refresh token securely.');
    await _storage.write(key: _keyRefresh, value: token, aOptions: _getAndroidOptions(), iOptions: _getIOSOptions());
  }

  Future<String?> readRefreshToken() async {
    logger.d('Reading refresh token from secure storage.');
    return await _storage.read(key: _keyRefresh, aOptions: _getAndroidOptions(), iOptions: _getIOSOptions());
  }

  Future<void> deleteRefreshToken() async {
    logger.d('Deleting refresh token from secure storage.');
    await _storage.delete(key: _keyRefresh, aOptions: _getAndroidOptions(), iOptions: _getIOSOptions());
  }

  Future<void> saveDeviceId(String deviceId) async {
    logger.d('Saving device ID securely: $deviceId');
    await _storage.write(key: _keyDeviceId, value: deviceId, aOptions: _getAndroidOptions(), iOptions: _getIOSOptions());
  }

  Future<String?> readDeviceId() async {
    logger.d('Reading device ID from secure storage.');
    return await _storage.read(key: _keyDeviceId, aOptions: _getAndroidOptions(), iOptions: _getIOSOptions());
  }

  Future<void> savePinHash(String pinHash) async {
    logger.d('Saving PIN hash securely.');
    await _storage.write(key: _keyPinHash, value: pinHash, aOptions: _getAndroidOptions(), iOptions: _getIOSOptions());
  }

  Future<String?> readPinHash() async {
    logger.d('Reading PIN hash from secure storage.');
    return await _storage.read(key: _keyPinHash, aOptions: _getAndroidOptions(), iOptions: _getIOSOptions());
  }

  Future<void> saveUserId(String userId) async {
    logger.d('Saving userId securely: $userId');
    await _storage.write(key: _keyUserId, value: userId, aOptions: _getAndroidOptions(), iOptions: _getIOSOptions());
  }

  Future<String?> readUserId() async {
    logger.d('Reading userId from secure storage.');
    return await _storage.read(key: _keyUserId, aOptions: _getAndroidOptions(), iOptions: _getIOSOptions());
  }

  Future<void> deleteAll() async {
    logger.d('Deleting all items from secure storage.');
    await _storage.deleteAll(aOptions: _getAndroidOptions(), iOptions: _getIOSOptions());
  }

  AndroidOptions _getAndroidOptions() => const AndroidOptions(
    encryptedSharedPreferences: true,
  );

  IOSOptions _getIOSOptions() => const IOSOptions(
    accountName: 'ECO-GUIDE',
    groupId: 'group.com.example.ecoguideauthapp', // Optional: for sharing between apps/extensions
  );
}