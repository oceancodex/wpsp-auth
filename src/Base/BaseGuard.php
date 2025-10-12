<?php

namespace WPSPCORE\Auth\Base;

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
		$this->provider    = $this->extraParams['provider'];
		$this->sessionKey  = $this->extraParams['session_key'];
		$this->guardName   = $this->extraParams['guard_name'] ?? 'web';
		$this->guardConfig = $this->extraParams['guard_config'] ?? [];
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

	abstract public function attempt($credentials = []);

	abstract public function id();

	abstract public function user();

	abstract public function check();

	/*
	 *
	 */

	public function logout() {
		if (in_array($this->guardConfig['driver'], ['session', 'sanctum'])) {
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
					'auth_user'    => $user,
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