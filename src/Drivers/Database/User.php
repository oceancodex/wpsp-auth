<?php

namespace WPSPCORE\Auth\Drivers\Database;

use WPSPCORE\Base\BaseInstances;
use WPSPCORE\Permission\Traits\DBPermissionTrait;

class User extends BaseInstances {

	use DBPermissionTrait;

	public $user;
	public $roles;
	public $permissions;
	public $roles_and_permissions;
	public $guard_name;

	public function afterInstanceConstruct(): void {
		$this->user                  = $this->customProperties['user'];
		$this->guard_name            = $this->customProperties['guard_name'];
		$this->roles                 = $this->roles();
		$this->permissions           = $this->permissions();
		$this->roles_and_permissions = $this->rolesAndPermissions();
	}

	public function id(): int {
		return $this->user->id ?? ($this->user->ID ?? 0);
	}

	public function toArray(): array {
		$data = is_object($this->user) ? get_object_vars($this->user) : (array)$this->user;

		$data['roles']                 = $this->roles;
		$data['permissions']           = $this->permissions;
		$data['roles_and_permissions'] = $this->roles_and_permissions;

		return $data;
	}

}