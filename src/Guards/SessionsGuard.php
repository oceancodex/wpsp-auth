<?php

namespace WPSPCORE\Auth\Guards;

use WPSPCORE\Auth\Providers\AccountsProvider;

class SessionsGuard {

	protected AccountsProvider $provider;
	protected string $sessionKey;

	public function __construct(AccountsProvider $provider, string $sessionKey = 'wpsp_auth_user_id') {
		$this->provider   = $provider;
		$this->sessionKey = $sessionKey;
	}

	/**
	 * credentials: ['login' => username|email, 'password' => string]
	 */
	public function attempt(array $credentials): bool {
		$user = $this->provider->retrieveByCredentials($credentials);

		// Trường mật khẩu của bảng accounts là 'password'
		if ($user && isset($credentials['password']) && wp_check_password($credentials['password'], $user->password)) {
			$_SESSION[$this->sessionKey] = (int) $user->id;
			return true;
		}
		return false;
	}

	public function user(): ?\stdClass {
		$id = $this->id();
		return $id ? $this->provider->retrieveById($id) : null;
	}

	public function check(): bool {
		return $this->id() !== null;
	}

	public function id(): ?int {
		return !empty($_SESSION[$this->sessionKey]) ? (int) $_SESSION[$this->sessionKey] : null;
	}

	public function logout(): void {
		unset($_SESSION[$this->sessionKey]);
	}
}