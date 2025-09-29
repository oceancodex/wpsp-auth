<?php

namespace WPSPCORE\Auth\Guards;

use WPSPCORE\Auth\Providers\UsersProvider;
use WPSPCORE\Base\BaseInstances;

class SessionsGuard extends BaseInstances {

	protected UsersProvider $provider;
	protected string        $sessionKey;
	protected string        $guardName; // Thêm thuộc tính này

	public function afterInstanceConstruct(): void {
		$this->provider   = $this->customProperties['provider'];
		$this->sessionKey = $this->customProperties['session_key'];
		$this->guardName  = $this->customProperties['guard_name'] ?? 'web'; // Thêm dòng này
	}

	/**
	 * credentials: ['login' => username|email, 'password' => string]
	 */
	public function attempt(array $credentials): bool {
		$user = $this->provider->retrieveByCredentials($credentials);
		if ($user && isset($credentials['password']) && wp_check_password($credentials['password'], $user->password)) {
			$_SESSION[$this->sessionKey] = (int)$user->id;
			return true;
		}
		return false;
	}

	public function user() {
		$id = $this->id();
		if (!$id) return null;

		$user = $this->provider->retrieveById($id);

		// Tự động set guard_name cho user object
		if ($user && is_object($user)) {
			$user->guard_name = $this->guardName;
		}

		return $user;
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