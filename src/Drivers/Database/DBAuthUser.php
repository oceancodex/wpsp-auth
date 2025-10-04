<?php

namespace WPSPCORE\Auth\Drivers\Database;

use WPSPCORE\Base\BaseInstances;
use WPSPCORE\Permission\Traits\DBPermissionTrait;

class DBAuthUser extends BaseInstances {

	use DBPermissionTrait;

	public $rawUser;
	public $roles;
	public $permissions;
	public $rolesAndPermissions;
	public $guardName;

	public function afterInstanceConstruct(): void {
		$this->guardName           = $this->customProperties['guard_name'];
		$this->rawUser             = $this->customProperties['raw_user'];
		$this->rawUser->guard_name = $this->guardName;
//		$this->roles               = $this->roles();
//		$this->permissions         = $this->permissions();
//		$this->rolesAndPermissions = $this->rolesAndPermissions();
	}

	public function id(): int {
		return $this->rawUser->id ?? ($this->rawUser->ID ?? 0);
	}

	public function toArray(): array {
		$data = is_object($this->rawUser) ? get_object_vars($this->rawUser) : (array)$this->rawUser;

//		$data['roles']                 = $this->roles;
//		$data['permissions']           = $this->permissions;
//		$data['roles_and_permissions'] = $this->rolesAndPermissions;

		return $data;
	}

}