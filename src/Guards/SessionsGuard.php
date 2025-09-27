<?php

namespace WPSPCORE\Auth\Guards;

use WPSPCORE\Auth\Providers\UsersProvider;
use WPSPCORE\Base\BaseInstances;

class SessionsGuard extends BaseInstances {

	protected UsersProvider $provider;
	protected string        $sessionKey;

	public function afterInstanceConstruct(): void {
		$this->provider   = $this->customProperties['provider'];
		$this->sessionKey = $this->customProperties['session_key'];
	}

	/**
	 * credentials: ['login' => username|email, 'password' => string]
	 */
	public function attempt(array $credentials): bool {
		$user = $this->provider->retrieveByCredentials($credentials);

		// Trường mật khẩu của bảng accounts là 'password'
		if ($user && isset($credentials['password']) && wp_check_password($credentials['password'], $user->password)) {
			$_SESSION[$this->sessionKey] = (int)$user->id;
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
		return !empty($_SESSION[$this->sessionKey]) ? (int)$_SESSION[$this->sessionKey] : null;
	}

	public function logout(): void {
		unset($_SESSION[$this->sessionKey]);
	}
}