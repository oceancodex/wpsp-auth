<?php

namespace WPSPCORE\Auth;

use WPSPCORE\Auth\Guards\TokensGuard;
use WPSPCORE\Base\BaseInstances;
use WPSPCORE\Auth\Guards\SessionsGuard;
use WPSPCORE\Auth\Providers\AuthServiceProvider;

class Auth extends BaseInstances {

	public $guards   = [];

	/*
	 *
	 */

	public function makeProvider($mainPath, $rootNamespace, $prefixEnv, $providerName, $configs) {
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

						'funcs'              => $this->funcs,
						'environment'        => null,
						'validation'         => null,

						'prepare_funcs'      => true,
						'prepare_request'    => false,

						'unset_funcs'        => false,
						'unset_request'      => true,
						'unset_validation'   => true,
						'unset_environment'  => true,

						'unset_extra_params' => true,
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

							'funcs'              => $this->funcs,
							'environment'        => null,
							'validation'         => null,

							'prepare_funcs'      => true,
							'prepare_request'    => false,

							'unset_funcs'        => false,
							'unset_request'      => true,
							'unset_validation'   => true,
							'unset_environment'  => true,

							'unset_extra_params' => true,
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

					'funcs'              => $this->funcs,
					'environment'        => null,
					'validation'         => null,

					'prepare_funcs'      => true,
					'prepare_request'    => false,

					'unset_funcs'        => false,
					'unset_request'      => true,
					'unset_validation'   => true,
					'unset_environment'  => true,

					'unset_extra_params' => true,
				]
			);
		}

		// Database provider
		if ($driver === 'database') {
			if ($authService) {
				return new $authService($mainPath, $rootNamespace, $prefixEnv, [
					'table'       => $table,
					'model_class' => null,

					'funcs'              => $this->funcs,
					'environment'        => null,
					'validation'         => null,

					'prepare_funcs'      => true,
					'prepare_request'    => false,

					'unset_funcs'        => false,
					'unset_request'      => true,
					'unset_validation'   => true,
					'unset_environment'  => true,

					'unset_extra_params' => true,
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

						'funcs'              => $this->funcs,
						'environment'        => null,
						'validation'         => null,

						'prepare_funcs'      => true,
						'prepare_request'    => false,

						'unset_funcs'        => false,
						'unset_request'      => true,
						'unset_validation'   => true,
						'unset_environment'  => true,

						'unset_extra_params' => true,
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

				'funcs'              => $this->funcs,
				'environment'        => null,
				'validation'         => null,

				'prepare_funcs'      => true,
				'prepare_request'    => false,

				'unset_funcs'        => false,
				'unset_request'      => true,
				'unset_validation'   => true,
				'unset_environment'  => true,

				'unset_extra_params' => true,
			]
		);
	}

	/*
	 *
	 */

	public function guard($name = null) {

		// Đọc toàn bộ config auth từ plugin chính (wpsp/config/auth.php).
		$configs = $this->funcs->_config('auth') ?? [];

		// Lấy tên guard mặc định nếu $name không truyền vào.
		$defaultName = $configs['defaults']['guard'] ?? 'web';
		$name        = $name ?: $defaultName;

		// Nếu guard chưa khởi tạo thì build theo config.
		if (!isset($this->guards[$name])) {
			$sessionKey = $this->funcs->_getAppShortName() . '_auth_' . $name . '_session_user_id';

			// Xác định provider được gán cho guard.
			$guardConfigName = $name;
			$guardConfig     = $configs['guards'][$guardConfigName] ?? null;
			$providerName    = $guardConfig['provider'] ?? ($configs['defaults']['provider'] ?? 'users');

			// Khởi tạo provider từ cấu hình.
			$provider = $this->makeProvider(
				$this->mainPath,
				$this->rootNamespace,
				$this->prefixEnv,
				$providerName,
				$configs
			);

			// Khởi tạo guard theo driver.
			$driver = $guardConfig['driver'] ?? 'session';

			// Session guard.
			if ($driver == 'session') {
				$this->guards[$name] = new SessionsGuard(
					$this->mainPath,
					$this->rootNamespace,
					$this->prefixEnv,
					[
						'provider'     => $provider,
						'session_key'  => $sessionKey,
						'guard_name'   => $name,
						'guard_config' => $guardConfig,

						'funcs'              => $this->funcs,
						'environment'        => null,
						'validation'         => null,

						'prepare_funcs'      => true,
						'prepare_request'    => false,

						'unset_funcs'        => false,
						'unset_request'      => true,
						'unset_validation'   => true,
						'unset_environment'  => true,

						'unset_extra_params' => true,
					]
				);
			}

			// Token guard.
			elseif ($driver == 'token') {
				$this->guards[$name] = new TokensGuard(
					$this->mainPath,
					$this->rootNamespace,
					$this->prefixEnv,
					[
						'provider'        => $provider,
						'guard_name'      => $name,
						'guard_config'    => $guardConfig,

						'funcs'              => $this->funcs,
						'environment'        => null,
						'validation'         => null,

						'prepare_funcs'      => true,
						'prepare_request'    => false,

						'unset_funcs'        => false,
						'unset_request'      => true,
						'unset_validation'   => true,
						'unset_environment'  => true,

						'unset_extra_params' => true,
					]
				);
			}

			// Sanctum guard.
			elseif ($driver == 'sanctum') {
				$this->guards[$name] = new \WPSPCORE\Sanctum\Sanctum(
					$this->mainPath,
					$this->rootNamespace,
					$this->prefixEnv,
					[
						'provider'     => $provider,
						'session_key'  => $sessionKey,
						'guard_name'   => $name,
						'guard_config' => $guardConfig,

						'funcs'              => $this->funcs,
						'environment'        => null,
						'validation'         => null,

						'prepare_funcs'      => true,
						'prepare_request'    => false,

						'unset_funcs'        => false,
						'unset_request'      => true,
						'unset_validation'   => true,
						'unset_environment'  => true,

						'unset_extra_params' => true,
					]
				);
			}

		}

		return $this->guards[$name];
	}

}