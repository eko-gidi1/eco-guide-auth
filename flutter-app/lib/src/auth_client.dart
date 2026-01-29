import 'dart:convert';
import 'package:dio/dio.dart';
import 'package:logger/logger.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:eco_guide_auth_app/src/env_config.dart'; // Import EnvConfig

var logger = Logger();

class AuthClient {
  final Dio _dio;
  AuthClient(String baseUrl)
      : _dio = Dio(BaseOptions(baseUrl: baseUrl, headers: {'Content-Type': 'application/json'})) {
    _dio.interceptors.add(InterceptorsWrapper(
      onRequest: (options, handler) {
        logger.d('Sending request: ${options.method} ${options.path}');
        handler.next(options);
      },
      onResponse: (response, handler) {
        logger.d('Received response: ${response.statusCode} for ${response.requestOptions.path}');
        handler.next(response);
      },
      onError: (err, handler) async {
        if (err.response?.statusCode == 429) {
          final retryAfterSeconds = int.tryParse(err.response?.headers.value('Retry-After') ?? '0') ?? 0;
          logger.w('Rate limited: Retrying after $retryAfterSeconds seconds for ${err.requestOptions.path}');
          // You might want to show a UI message here or queue the request
          return handler.next(DioException(
            requestOptions: err.requestOptions,
            response: err.response,
            type: DioExceptionType.cancel, // Or a custom type to indicate rate limit
            error: {'message': 'Too many requests. Please try again after $retryAfterSeconds seconds.', 'retry_after': retryAfterSeconds},
          ));
        } else if (err.response?.statusCode == 500) {
          logger.e('Server error for ${err.requestOptions.path}: ${err.response?.data}');
          // Potentially launch support URL
          if (EnvConfig.supportUrl.isNotEmpty) {
            await launchUrl(Uri.parse(EnvConfig.supportUrl));
          }
        }
        logger.e('Error for ${err.requestOptions.path}: ${err.message}');
        handler.next(err); // Continue with the error
      },
    ));
  }

  Future<Response> _post(String path, Map<String, dynamic> body) {
    return _dio.post(path, data: jsonEncode(body));
  }

  // API Contracts:
  // POST /auth/otp/request
  Future<Map<String, dynamic>> requestOtp(String identifier, String channel, String tempUserId, String clientIp) async {
    final resp = await _post('/auth/otp/request', {
      'identifier': identifier,
      'channel': channel,
      'temp_user_id': tempUserId,
      'client_ip': clientIp,
    });
    return resp.data as Map<String, dynamic>;
  }

  // POST /auth/otp/verify
  Future<Map<String, dynamic>> verifyOtp(String identifier, String otp, String tempUserId, String deviceId) async {
    final resp = await _post('/auth/otp/verify', {
      'identifier': identifier,
      'otp': otp,
      'temp_user_id': tempUserId,
      'device_id': deviceId,
    });
    return resp.data as Map<String, dynamic>;
  }

  // POST /auth/consent
  Future<Map<String, dynamic>> submitConsent(String tempUserId, bool consent) async {
    final resp = await _post('/auth/consent', {
      'temp_user_id': tempUserId,
      'consent': consent,
    });
    return resp.data as Map<String, dynamic>;
  }

  // POST /auth/token/refresh
  Future<Map<String, dynamic>> refreshToken(String refreshToken) async {
    final resp = await _post('/auth/token/refresh', {'refresh_token': refreshToken});
    return resp.data as Map<String, dynamic>;
  }

  // POST /auth/token/revoke
  Future<Map<String, dynamic>> revokeToken({String? refreshToken, String? userId, String? deviceId}) async {
    final body = <String, dynamic>{};
    if (refreshToken != null) body['refresh_token'] = refreshToken;
    if (userId != null) body['user_id'] = userId;
    if (deviceId != null) body['device_id'] = deviceId;
    final resp = await _post('/auth/token/revoke', body);
    return resp.data as Map<String, dynamic>;
  }

  // POST /auth/introspect
  Future<Map<String, dynamic>> introspectToken(String token) async {
    final resp = await _post('/auth/introspect', {'token': token});
    return resp.data as Map<String, dynamic>;
  }
}