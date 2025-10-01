<?php

namespace WPSPCORE\Auth\Guards;

use WPSPCORE\Auth\Drivers\Database\User;
use WPSPCORE\Auth\Providers\AuthServiceProvider;
use WPSPCORE\Base\BaseInstances;
use WPSPCORE\Permission\Traits\PermissionTrait;

class SessionsGuard extends BaseInstances {

	public ?User $DBAuthUser = null;

	protected AuthServiceProvider $provider;
	protected string              $sessionKey;
	protected string        $guardName;

	/*
	 *
	 */

	public function afterInstanceConstruct(): void {
		$this->provider   = $this->customProperties['provider'];
		$this->sessionKey = $this->customProperties['session_key'];
		$this->guardName  = $this->customProperties['guard_name'] ?? 'web';
	}

	/*
	 *
	 */

	public function attempt(array $credentials): bool {
		$user = $this->provider->retrieveByCredentials($credentials);
		if ($user && isset($credentials['password']) && wp_check_password($credentials['password'], $user->password)) {
			$_SESSION[$this->sessionKey] = (int)$user->id;
			return true;
		}
		return false;
	}

	/*
	 *
	 */

	/**
	 * @return array|\Illuminate\Database\Eloquent\Model|object|\stdClass|null|PermissionTrait
	 */
	public function user() {
		$id = $this->id();
		if (!$id) return null;

		$user = $this->provider->retrieveById($id);

		// Tự động set guard_name cho user object
		if ($user && is_object($user)) {
			$user->guard_name = $this->guardName;
		}

		if ($user instanceof \stdClass) {
			if (!($this->DBAuthUser instanceof User) || $this->DBAuthUser->raw !== $user) {
				$this->DBAuthUser = new User(
					$this->funcs->_getMainPath(),
					$this->funcs->_getRootNamespace(),
					$this->funcs->_getPrefixEnv(),
					[
						'user' => $user,
					]
				);
			}
			return $this->DBAuthUser;
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

	/*
	 *
	 */

	public function getProvider () {
		return $this->provider;
	}

}