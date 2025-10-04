<?php

namespace WPSPCORE\Auth\Guards;

use WPSPCORE\Auth\Base\BaseGuard;
use WPSPCORE\Auth\Drivers\Database\DBAuthUser;
use WPSPCORE\Permission\Traits\PermissionTrait;

class TokensGuard extends BaseGuard {
	private ?DBAuthUser $DBAuthUser = null;

	/**
	 * @return array|\Illuminate\Database\Eloquent\Model|object|\stdClass|null|PermissionTrait
	 */
	public function user() {
		if (!$this->rawUser) return null;

		if ($this->rawUser instanceof \stdClass) {
			if (!($this->DBAuthUser instanceof DBAuthUser) || $this->DBAuthUser->rawUser !== $this->rawUser) {
				$this->DBAuthUser = new DBAuthUser(
					$this->funcs->_getMainPath(),
					$this->funcs->_getRootNamespace(),
					$this->funcs->_getPrefixEnv(),
					[
						'guard_name' => $this->guardName,
						'raw_user'   => $this->rawUser,
					]
				);
			}

			return $this->DBAuthUser;
		}
		else {
			// Add guard name.
			$this->rawUser->setAttribute('guard_name', $this->guardName);
//			$this->rawUser->guard_name = $this->guardName;
		}

		return $this->rawUser;
	}

}