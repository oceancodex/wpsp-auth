<?php

namespace WPSPCORE\Auth\Guards;

use WPSPCORE\Auth\Base\BaseGuard;
use WPSPCORE\Auth\Models\DBAuthUser;

class TokensGuard extends BaseGuard {

	private ?DBAuthUser $DBAuthUser = null;

	public function user() {
		if (!$this->authUser) return null;

		if ($this->authUser instanceof \stdClass) {
			if (!($this->DBAuthUser instanceof DBAuthUser) || $this->DBAuthUser->authUser !== $this->authUser) {
				$this->DBAuthUser = new DBAuthUser(
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