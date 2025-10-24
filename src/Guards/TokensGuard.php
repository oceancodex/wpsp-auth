<?php

namespace WPSPCORE\Auth\Guards;

use WPSPCORE\Auth\Base\BaseGuard;
use WPSPCORE\Auth\Models\DBAuthUserModel;

class TokensGuard extends BaseGuard {

	public function attempt($credentials = []) {
		// Prepare credentials.
		if (empty($credentials)) {
			$credentials             = [];
			$credentials['login']    = $this->request->get('login');
			$credentials['password'] = $this->request->get('password');
		}

		// Get user by credentials, do not assign session.
		if ($credentials['login'] && $credentials['password']) {
			$user = $this->provider->retrieveByCredentials($credentials);
			if ($user) {
				$this->authUser = $this->prepareUser($user, DBAuthUserModel::class);
				return $this;
			}
		}

		// Get user by token.
		else {
			$apiToken = $this->funcs->_getBearerToken();
			if ($apiToken) {
				$user = $this->provider->retrieveByToken($apiToken);
				if (!$user) return false;
				$this->authUser = $this->prepareUser($user, DBAuthUserModel::class);
				return $this;
			}
		}

		return false;
	}

	/*
	 *
	 */

	public function id() {
		return $this->authUser->id ?? $this->authUser->ID ?? null;
	}

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

	public function check() {
		if (!$this->authUser) {
			$this->attempt();
		}
		return $this->id() !== null;
	}

}