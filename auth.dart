import 'dart:collection';

import 'package:dio/dio.dart';
import 'package:get/get.dart';
import '../../../config/routes/route_path/auth_routers.dart';
import '../../../config/routes/route_path/base_routers.dart';
import '../../../core/di_container.dart';
import '../../../core/shared_pref/auth/auth_shared_preference.dart';
import '../../../core/shared_pref/shared_preference_helper.dart';
import '../../../domain/end_points/end_point.dart';
import '../../lookup_data.dart';
import '../../repositories/base/jwt_repo.dart';
import 'dio_client.dart';

class AuthInterceptor extends InterceptorsWrapper {
  final DioClient dioClient;
  final JwtRepoImpl jwtRepoImpl;

  AuthInterceptor(this.dioClient, this.jwtRepoImpl);

  bool _isRefreshing = false;
  final _authStorage = sl.get<AuthSharedPreference>();

  final _pendingRequests = Queue<({RequestOptions options, ErrorInterceptorHandler handler})>();

  @override
  void onRequest(RequestOptions options, RequestInterceptorHandler handler) async {
    final token = options.headers['Authorization'];

    if (token == null || token.isEmpty) {
      final accessToken = await _authStorage.getJwtToken;

      options.headers['Authorization'] = 'Bearer $accessToken';
    }

    Get.log('Request XXX: ${options.method} - ${options.uri}');

    handler.next(options);
  }

  @override
  void onError(DioException err, ErrorInterceptorHandler handler) async {
    final response = err.response;
    final uri = response?.requestOptions.path;

    if (response?.statusCode == 401 && uri != EndPoints.refreshToken) {
      _pendingRequests.add((options: response!.requestOptions, handler: handler));

      if (!_isRefreshing) {
        _isRefreshing = true;

        final result = await jwtRepoImpl.refreshToken();

        await result.fold(
          (error) async {
            while (_pendingRequests.isNotEmpty) {
              final req = _pendingRequests.removeFirst();

              req.handler.reject(err);
            }

            await _removeLocalDataAndLogout();
          },
          (user) async {
            while (_pendingRequests.isNotEmpty) {
              final req = _pendingRequests.removeFirst();

              final accessToken = await _authStorage.getJwtToken;

              req.options.headers['Authorization'] = 'Bearer $accessToken';

              try {
                final response = await dioClient.fetchFreshToken(req.options);

                req.handler.resolve(response);
              } catch (e) {
                req.handler.reject(e as DioException);
              }
            }
          },
        );

        _isRefreshing = false;
      }
    } else {
      handler.next(err);
    }
  }

  Future<void> _removeLocalDataAndLogout() async {
    await Future.wait([
      sl<AuthSharedPreference>().removeJwtToken(),
      sl<AuthSharedPreference>().removeLogger(),
      sl<AuthSharedPreference>().removeIdUser(),
      sl<SharedPreferenceHelper>().removeSpecialBoots(),
      sl<SharedPreferenceHelper>().removeWelcomeCoin(),
      sl<SharedPreferenceHelper>().removeSpecialSupperLike(),
      sl<SharedPreferenceHelper>().removeIsShowBoostAgain(),
    ]);

    LookUpData.expiresAt = null;

    final bool ignoreRouter = [
      BaseRouters.SPLASH,
      BaseRouters.INTRODUCTION,
      AuthRouters.LOGIN,
    ].contains(Get.currentRoute);

    if (ignoreRouter) return;

    Get.offAllNamed(AuthRouters.LOGIN);
  }
}
