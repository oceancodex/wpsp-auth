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

		// Helper lấy giá trị field từ Model/stdClass/mảng
		$get = static function($obj, string $field) {
			if ($obj instanceof \Illuminate\Database\Eloquent\Model) {
				return $obj->getAttribute($field);
			}
			if (is_object($obj)) {
				return $obj->{$field} ?? null;
			}
			if (is_array($obj)) {
				return $obj[$field] ?? null;
			}
			return null;
		};

		// Duyệt các cặp field password đã cấu hình
		foreach ($this->provider->dbPasswordFields as $dbPasswordField) {
			$hashed = $get($user, $dbPasswordField);
			if (!$hashed) continue;

			foreach ($this->provider->formPasswordFields as $formPasswordField) {
				$given = $credentials[$formPasswordField] ?? null;
				if ($given !== null && wp_check_password($given, (string)$hashed)) {
					// Cache user cho request hiện tại (stateless)
					$this->cachedRawUser = $user instanceof \Illuminate\Database\Eloquent\Model
						? (object)$user->toArray()
						: (is_object($user) ? $user : (object)$user);

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