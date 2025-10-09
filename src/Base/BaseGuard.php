<?php

namespace WPSPCORE\Auth\Base;

use WPSPCORE\Auth\Models\DBAuthUserModel;
use WPSPCORE\Base\BaseInstances;

abstract class BaseGuard extends BaseInstances {

	/** @var \WPSPCORE\Auth\Providers\AuthServiceProvider */
	protected $provider;
	protected $sessionKey;
	protected $guardName;
	protected $guardConfig;

	/** @var \WPSPCORE\Auth\Drivers\Database\DBAuthUser|\Illuminate\Database\Eloquent\Model|null */
	protected $authUser;

	/*
	 *
	 */

	public function afterInstanceConstruct() {
		$this->provider    = $this->customProperties['provider'];
		$this->sessionKey  = $this->customProperties['session_key'];
		$this->guardName   = $this->customProperties['guard_name'] ?? 'web';
		$this->guardConfig = $this->customProperties['guard_config'] ?? [];
	}

	/*
	 *
	 */

	public function __get($name) {
		if ($name == 'user') return $this->user();
		return null;
	}

	/*
	 *
	 */

	abstract public function user();

	abstract public function attempt(array $credentials = []);

	/*
	 *
	 */

	public function id() {
		if ($this->guardConfig['driver'] == 'session') {
			return !empty($_SESSION[$this->sessionKey]) ? (int)$_SESSION[$this->sessionKey] : null;
		}
		elseif ($this->guardConfig['driver'] == 'token') {
			if ($this->authUser === null) {
				$this->attempt();
			}
			return $this->authUser->id;
		}
		return null;
	}

	public function check(): bool {
//		if ($this->guardConfig['driver'] == 'token') {
//			$apiToken = $this->funcs->_getBearerToken();
//			$user     = $this->provider->retrieveByToken($apiToken);
//			if ($user) return true;
//		}
		return $this->id() !== null;
	}

	public function logout(): true {
		if ($this->guardConfig['driver'] == 'session') {
			unset($_SESSION[$this->sessionKey]);
		}
		elseif ($this->guardConfig['driver'] == 'sanctum') {
			unset($_SESSION[$this->sessionKey]);
		}
		elseif ($this->guardConfig['driver'] == 'token') {
			$this->authUser = null;
		}
		return true;
	}

	public function prepareUser($user, $dbModelClass) {
		if ($user instanceof \stdClass) {
			$user = new $dbModelClass(
				$this->funcs->_getMainPath(),
				$this->funcs->_getRootNamespace(),
				$this->funcs->_getPrefixEnv(),
				[
					'auth_user'    => $this->authUser,
					'provider'     => $this->provider,
					'session_key'  => $this->sessionKey,
					'guard_name'   => $this->guardName,
					'guard_config' => $this->guardConfig,
				]
			);
		}
		else {
			// Add guard name.
			$user->setAttribute('guard_name', $this->guardName);
		}

		return $user;
	}

}