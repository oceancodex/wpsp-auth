<?php

namespace WPSPCORE\Auth;

use WPSPCORE\Base\BaseInstances;
use WPSPCORE\Auth\Guards\SessionsGuard;
use WPSPCORE\Auth\Providers\AuthServiceProvider;

class Auth extends BaseInstances {

	protected array $guards = [];

	public function guard(?string $name = null): SessionsGuard {

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

			// Khởi tạo guard dựa trên driver (mặc định session)
			$driver = $guardConfig['driver'] ?? 'session';

			// Hiện tại chỉ hỗ trợ session guard
			$this->guards[$name] = new SessionsGuard(
				$this->mainPath,
				$this->rootNamespace,
				$this->prefixEnv,
				[
					'provider'    => $provider,
					'session_key' => $sessionKey,
					'guard_name'  => $name, // Thêm dòng này
				]
			);
		}

		return $this->guards[$name];
	}

	/**
	 * Tạo provider theo tên từ mảng config auth.
	 * Hỗ trợ:
	 * - driver = 'eloquent': sử dụng model được chỉ định trong config
	 * - driver = 'database': sử dụng bảng chỉ định (tối thiểu cần 'table')
	 * - fallback: AccountsProvider mặc định (đọc từ bảng accounts tùy chỉnh)
	 */
	protected static function makeProvider(string $mainPath, string $rootNamespace, string $prefixEnv, string $providerName, array $configs) {
		$providers = $configs['providers'] ?? [];
		$provider  = $providers[$providerName] ?? null;

		if (!$provider || !isset($provider['driver'])) {
			return new AuthServiceProvider(
				$mainPath,
				$rootNamespace,
				$prefixEnv,
				[
					'table' => 'cm_users'
				]
			);
		}

		$driver = $provider['driver'];

		// Eloquent provider
		if ($driver === 'eloquent') {
			$modelClass = $provider['model'] ?? null;
			$table = 'cm_users';
			if ($modelClass && class_exists($modelClass)) {
				return new AuthServiceProvider(
					$mainPath,
					$rootNamespace,
					$prefixEnv,
					[
						'table' => $table,
						'options' => [
							'model_class' => $modelClass
						]
					]
				);
			}
			return new AuthServiceProvider(
				$mainPath,
				$rootNamespace,
				$prefixEnv,
				[
					'table' => $table,
					'options' => [
						'model_class' => $modelClass
					]
				]
			);
		}

		// Database provider
		if ($driver === 'database') {
			$table = $provider['table'] ?? 'cm_users';
			return new AuthServiceProvider(
				$mainPath,
				$rootNamespace,
				$prefixEnv,
				[
					'table' => $table,
				]
			);
		}

		// Mặc định
		return new AuthServiceProvider($mainPath, $rootNamespace, $prefixEnv);
	}

}