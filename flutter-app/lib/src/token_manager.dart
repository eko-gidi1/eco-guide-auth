import 'dart:async';
import 'package:logger/logger.dart';
import 'package:eco_guide_auth_app/src/secure_storage.dart';
import 'package:eco_guide_auth_app/src/auth_client.dart';

var logger = Logger();

class TokenManager {
  final SecureStorage _storage;
  final AuthClient _client;

  String? _accessToken;
  DateTime? _accessExpiry;
  Future<void>? _refreshLock; // For one-flight refresh to prevent race conditions

  TokenManager(this._storage, this._client);

  String? get accessToken => _accessToken;
  // It's better to read userId from secure storage when needed, or keep it in a state management solution.
  // For simplicity, a direct read here:
  Future<String?> getUserId() => _storage.readUserId(); 

  // Check if current access token is still valid
  bool get accessValid => _accessToken != null && _accessExpiry != null && DateTime.now().isBefore(_accessExpiry!);

  // Call after successful OTP verification or refresh
  Future<void> setTokens({
    required String accessToken,
    required int accessExpiresInSeconds,
    required String refreshToken,
    required String userId,
  }) async {
    _accessToken = accessToken;
    _accessExpiry = DateTime.now().add(Duration(seconds: accessExpiresInSeconds));
    await _storage.saveRefreshToken(refreshToken);
    await _storage.saveUserId(userId);
    logger.i('Tokens set. Access expires at $_accessExpiry');
  }

  // Ensures there is a valid access token, refreshes if necessary.
  // Handles one-flight refresh logic to prevent multiple concurrent refreshes.
  Future<void> ensureAccessToken() async {
    if (accessValid) {
      logger.d('Access token is valid. No refresh needed.');
      return;
    }

    // If a refresh is already in progress, await it.
    if (_refreshLock != null) {
      logger.d('Refresh already in progress, awaiting existing refresh lock.');
      return _refreshLock!;
    }

    // Start a new refresh operation and lock it.
    _refreshLock = _doRefresh();
    try {
      await _refreshLock;
    } on Exception catch (e) {
      logger.e('Failed to refresh token: $e');
      rethrow;
    } finally {
      _refreshLock = null; // Release the lock
    }
  }

  // Performs the actual token refresh call to the backend.
  Future<void> _doRefresh() async {
    logger.i('Attempting to refresh token...');
    final refresh = await _storage.readRefreshToken();
    if (refresh == null) {
      logger.w('No refresh token found. User must re-authenticate.');
      throw Exception('NO_REFRESH_TOKEN'); // User needs to log in again
    }

    try {
      final resp = await _client.refreshToken(refresh);
      // Server returns new access & refresh tokens
      await setTokens(
        accessToken: resp['access_token'],
        accessExpiresInSeconds: resp['expires_in'] ?? 900, // Default 15 min
        refreshToken: resp['refresh_token'],
        userId: resp['user_id'] // Assuming backend returns user_id with tokens
      );
      logger.i('Token refresh successful.');
    } catch (e) {
      logger.e('Error during token refresh: $e');
      await clearAll(); // Invalidate local tokens on refresh failure
      rethrow;
    }
  }

  // Clears all local tokens (access and refresh) and user ID.
  Future<void> clearAll() async {
    logger.i('Clearing all local tokens and user ID.');
    _accessToken = null;
    _accessExpiry = null;
    await _storage.deleteAll(); // Delete refresh token and user ID
  }
}