import 'package:logger/logger.dart';
import 'package:eco_guide_auth_app/src/auth_client.dart';
import 'package:eco_guide_auth_app/src/device_utils.dart';
import 'package:uuid/uuid.dart';

var logger = Logger();

class OtpService {
  final AuthClient _client;
  String? _tempUserId; // Hold tempUserId for the duration of the OTP flow

  OtpService(this._client);

  // Initiates the OTP request flow. Generates a temp_user_id if not already present.
  Future<Map<String, dynamic>> requestOtp(String identifier, String channel, String clientIp) async {
    _tempUserId ??= const Uuid().v4(); // Generate once per flow
    logger.i('Requesting OTP for identifier $identifier via $channel with tempUserId $_tempUserId');
    try {
      final resp = await _client.requestOtp(identifier, channel, _tempUserId!, clientIp);
      return resp;
    } catch (e) {
      logger.e('Failed to request OTP: $e');
      rethrow;
    }
  }

  // Verifies the OTP provided by the user.
  Future<Map<String, dynamic>> verifyOtp(String identifier, String otp) async {
    if (_tempUserId == null) {
      logger.e('No temporary user ID found for OTP verification. Request OTP first.');
      throw Exception('NO_TEMP_USER_ID');
    }

    final deviceId = await DeviceUtils.getOrCreateDeviceId(); // Get stable device ID
    logger.i('Verifying OTP for identifier $identifier with tempUserId $_tempUserId, deviceId $deviceId');
    try {
      final resp = await _client.verifyOtp(identifier, otp, _tempUserId!, deviceId);
      // _tempUserId is cleared after successful verification, but we need it for consent next.
      // So, we'll clear it after consent is fully processed.
      return resp;
    } catch (e) {
      logger.e('Failed to verify OTP: $e');
      rethrow;
    }
  }

  // Returns the current temporary user ID, or null if not in an OTP flow.
  String? getCurrentTempUserId() => _tempUserId;

  // Resets the OTP flow, e.g., if the user cancels or wants to restart.
  void resetOtpFlow() {
    _tempUserId = null;
    logger.i('OTP flow reset.');
  }
}