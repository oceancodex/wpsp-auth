<?php

namespace WPSPCORE\Auth;

use WPSP\Funcs;
use WPSPCORE\Auth\Guards\SessionsGuard;
use WPSPCORE\Auth\Providers\AccountsProvider;

class Auth {

	protected static array $guards = [];

	public static function guard(?string $name = null): SessionsGuard {
		if (session_status() === PHP_SESSION_NONE) {
			if (!headers_sent()) {
				@session_start();
			}
		}

		$configs     = Funcs::config('auth');
		$defaultName = $configs['defaults']['guard'] ?? 'web';
		$name        = $name ?: $defaultName;

		if (!isset(self::$guards[$name])) {
			$sessionKey = (Funcs::instance()->_getAppShortName() ?: 'wpsp') . '_auth_user_id';

			// Provider đọc từ bảng accounts tùy chỉnh.
			$provider = new AccountsProvider();

			self::$guards[$name] = new SessionsGuard($provider, $sessionKey);
		}

		return self::$guards[$name];
	}

	public static function user() {
		return self::guard()->user();
	}

	public static function check(): bool {
		return self::guard()->check();
	}

	public static function logout(): void {
		self::guard()->logout();
	}

	public static function id(): ?int {
		return self::guard()->id();
	}
}