<?php

namespace WPSPCORE\Auth\Base;

use WPSPCORE\Base\BaseInstances;

abstract class BaseGuard extends BaseInstances {

	protected $provider;
	protected $sessionKey;
	protected $guardName;
	protected $guardConfig;

	protected $rawUser;

	/*
	 *
	 */

	public function afterInstanceConstruct(): void {
		$this->provider    = $this->customProperties['provider'];
		$this->sessionKey  = $this->customProperties['session_key'];
		$this->guardName   = $this->customProperties['guard_name'] ?? 'web';
		$this->guardConfig = $this->customProperties['guard_config'] ?? [];
	}

	/*
	 *
	 */

	public function __get($name) {
		if ($name === 'user') return $this->user();
		return null;
	}

	/*
	 *
	 */

	abstract public function user();

	/*
	 *
	 */

	public function id() {
		if ($this->guardConfig['driver'] == 'session') {
			return !empty($_SESSION[$this->sessionKey]) ? (int)$_SESSION[$this->sessionKey] : null;
		}
		elseif ($this->guardConfig['driver'] == 'token') {
			return $this->rawUser->id;
		}
		return null;
	}

	public function check(): bool {
		return $this->id() !== null;
	}

	public function logout(): true {
		if ($this->guardConfig['driver'] == 'session') {
			unset($_SESSION[$this->sessionKey]);
		}
		elseif ($this->guardConfig['driver'] == 'token') {
			$this->rawUser = null;
		}
		return true;
	}

	public function attempt(array $credentials = []): bool|static {
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

					if ($this->guardConfig['driver'] == 'session') {
						$_SESSION[$this->sessionKey] = $id;
						return true;
					}
					elseif ($this->guardConfig['driver'] == 'token') {
						$this->rawUser = $user;
						return $this;
					}
				}
			}
		}
		return false;
	}

}