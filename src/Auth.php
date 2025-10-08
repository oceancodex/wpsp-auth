<?php

namespace WPSPCORE\Auth;

use WPSPCORE\Auth\Guards\TokensGuard;
use WPSPCORE\Base\BaseInstances;
use WPSPCORE\Auth\Guards\SessionsGuard;
use WPSPCORE\Auth\Providers\AuthServiceProvider;

class Auth extends BaseInstances {

	protected array $guards = [];

	public function guard(?string $name = null) {

		// Đọc toàn bộ config auth từ plugin chính (wpsp/config/auth.php)
		$configs = $this->funcs->_config('auth') ?? [];

		// Lấy tên guard mặc định nếu $name không truyền vào
		$defaultName = $configs['defaults']['guard'] ?? 'web';
		$name        = $name ?: $defaultName;

		// Nếu guard chưa khởi tạo thì build theo config
		if (!isset($this->guards[$name])) {
			$sessionKey = $this->funcs->_getAppShortName() . '_auth_' . $name . '_session_user_id';

			// Xác định provider được gán cho guard
			$guardConfigName = $name;
			$guardConfig     = $configs['guards'][$guardConfigName] ?? null;
			$providerName    = $guardConfig['provider'] ?? ($configs['defaults']['provider'] ?? 'users');

			// Khởi tạo provider từ cấu hình
			$provider = self::makeProvider(
				$this->mainPath,
				$this->rootNamespace,
				$this->prefixEnv,
				$providerName,
				$configs
			);

			// Khởi tạo guard theo driver
			$driver = $guardConfig['driver'] ?? 'session';

			// Sanctum guard
			if ($driver === 'sanctum') {
				$this->guards[$name] = new \WPSPCORE\Sanctum\Sanctum(
					$this->mainPath,
					$this->rootNamespace,
					$this->prefixEnv,
					[
						'provider'     => $provider,
						'session_key'  => $sessionKey,
						'guard_name'   => $name,
						'guard_config' => $guardConfig,
					]
				);
			}
			// Token guard
			elseif ($driver === 'token') {
				$this->guards[$name] = new TokensGuard(
					$this->mainPath,
					$this->rootNamespace,
					$this->prefixEnv,
					[
						'provider'     => $provider,
						'guard_name'   => $name,
						'guard_config' => $guardConfig,
					]
				);
			}
			// Session guard (default)
			else {
				$this->guards[$name] = new SessionsGuard(
					$this->mainPath,
					$this->rootNamespace,
					$this->prefixEnv,
					[
						'provider'     => $provider,
						'session_key'  => $sessionKey,
						'guard_name'   => $name,
						'guard_config' => $guardConfig,
					]
				);
			}
		}

		return $this->guards[$name];
	}

	public static function makeProvider(string $mainPath, string $rootNamespace, string $prefixEnv, string $providerName, array $configs) {
		$providers = $configs['providers'] ?? [];
		$provider  = $providers[$providerName] ?? null;

		if (!$provider || !isset($provider['driver'])) {
			return new AuthServiceProvider(
				$mainPath,
				$rootNamespace,
				$prefixEnv,
				[
					'table'       => 'cm_users',
					'model_class' => null,
				]
			);
		}

		$driver      = $provider['driver'];
		$table       = $provider['table'] ?? null;
		$authService = $provider['auth_service'] ?? null;

		// Eloquent provider
		if ($driver === 'eloquent') {
			$modelClass = $provider['model'] ?? null;
			if ($modelClass && class_exists($modelClass)) {
				if ($authService) {
					return new $authService($mainPath, $rootNamespace, $prefixEnv, [
						'table'       => $table,
						'model_class' => $modelClass,
					]);
				}
				else {
					return new AuthServiceProvider(
						$mainPath,
						$rootNamespace,
						$prefixEnv,
						[
							'table'       => $table,
							'model_class' => $modelClass,
						]
					);
				}
			}
			return new AuthServiceProvider(
				$mainPath,
				$rootNamespace,
				$prefixEnv,
				[
					'table'       => $table,
					'model_class' => $modelClass,
				]
			);
		}

		// Database provider
		if ($driver === 'database') {
			if ($authService) {
				return new $authService($mainPath, $rootNamespace, $prefixEnv, [
					'table'       => $table,
					'model_class' => null,
				]);
			}
			else {
				return new AuthServiceProvider(
					$mainPath,
					$rootNamespace,
					$prefixEnv,
					[
						'table'       => $table,
						'model_class' => null,
					]
				);
			}
		}

		// Mặc định
		return new AuthServiceProvider(
			$mainPath,
			$rootNamespace,
			$prefixEnv,
			[
				'table'       => $table,
				'model_class' => null,
			]
		);
	}

}