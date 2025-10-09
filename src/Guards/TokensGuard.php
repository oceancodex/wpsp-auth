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
			$this->authUser = $this->prepareUser($user, DBAuthUserModel::class);
			return $this;
		}
		return false;
	}

	/*
	 *
	 */

	public function user() {
		if (!$this->authUser) {
			$this->attempt();
		}

		if (!$this->authUser) return null;

		if ($this->authUser instanceof DBAuthUserModel) {
			return $this->authUser;
		}
		else {
			// Add guard name.
			$this->authUser->setAttribute('guard_name', $this->guardName);
//			$this->authUser->guard_name = $this->guardName;
		}

		return $this->authUser;
	}

	public function check(): bool {
		$apiToken = $this->funcs->_getBearerToken();
		$user     = $this->provider->retrieveByToken($apiToken);
		if ($user) return true;
		return false;
	}

	public function id(): int {
		return (int)$this->authUser->id;
	}

}