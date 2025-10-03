<?php

namespace WPSPCORE\Auth\Guards;

use WPSPCORE\Auth\Drivers\Database\User;
use WPSPCORE\Auth\Providers\AuthServiceProvider;
use WPSPCORE\Base\BaseInstances;
use WPSPCORE\Permission\Traits\PermissionTrait;

class SessionsGuard extends BaseInstances {

	private ?User   $DBAuthUser    = null;
	private ?object $cachedRawUser = null;

	protected AuthServiceProvider $provider;
	protected string              $sessionKey;
	protected string              $guardName;

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
		if (!$user) return false;

		foreach ($this->provider->dbPasswordFields as $dbPasswordField) {
			foreach ($this->provider->formPasswordFields as $formPasswordField) {
				$given  = $credentials[$formPasswordField] ?? null;
				$hashed = $user->{$dbPasswordField} ?? null;
				if ($given !== null && $hashed && wp_check_password($given, $hashed)) {
					$id = null;
					foreach ($this->provider->dbIdFields as $dbIdField) {
						try {
							$id = $user->{$dbIdField} ?? null;
						}
						catch (\Exception $e) {
							continue;
						}
						if ($id) break;
					}
					if ($id === null) return false;
					$_SESSION[$this->sessionKey] = $id;
					return true;
				}
			}
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

		if ($this->cachedRawUser && ((int)($this->cachedRawUser->id ?? $this->cachedRawUser->ID ?? 0)) === $id) {
			$user = $this->cachedRawUser;
		}
		else {
			$user = $this->provider->retrieveById($id);
			$this->cachedRawUser = $user instanceof \stdClass ? $user : null;
		}

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

	public function getProvider() {
		return $this->provider;
	}

}