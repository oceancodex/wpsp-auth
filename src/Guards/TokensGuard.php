<?php

namespace WPSPCORE\Auth\Guards;

use WPSPCORE\Auth\Base\BaseGuard;
use WPSPCORE\Auth\Models\DBAuthUserModel;

class TokensGuard extends BaseGuard {

	private ?DBAuthUserModel $DBAuthUser = null;

	public function attempt(array $credentials = []) {
		$apiToken = $this->funcs->_getBearerToken();
		if ($apiToken) {
			$user = $this->provider->retrieveByToken($apiToken);
			if (!$user) return false;
			$this->authUser = $user;
			return $this;
		}
		return false;
	}

	public function user() {
		if ($this->authUser === null) {
			$this->attempt();
		}

		if (!$this->authUser) return null;

		if ($this->authUser instanceof \stdClass) {
			if (!($this->DBAuthUser instanceof DBAuthUserModel) || $this->DBAuthUser->authUser !== $this->authUser) {
				$this->DBAuthUser = new DBAuthUserModel(
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

			return $this->DBAuthUser;
		}
		else {
			// Add guard name.
			$this->authUser->setAttribute('guard_name', $this->guardName);
//			$this->authUser->guard_name = $this->guardName;
		}

		return $this->authUser;
	}

}