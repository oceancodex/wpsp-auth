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

	public function afterInstanceConstruct(): void {
		$this->user = $this->customProperties['user'];

		if (method_exists($this, 'roles')) {
			$this->roles = $this->roles();
		}

		if (method_exists($this, 'permissions')) {
			$this->permissions = $this->permissions();
		}

		if (method_exists($this, 'rolesAndPermissions')) {
			$this->roles_and_permissions = $this->rolesAndPermissions();
		}

	}

	public function id(): int {
		return $this->user->id;
	}

	public function toArray(): array {
		$data = is_object($this->user) ? get_object_vars($this->user) : (array)$this->user;

		$data['id']    = $this->id();
		$data['roles'] = $this->roles;

		if (method_exists($this, 'permissions')) {
			$data['permissions'] = $this->permissions;
		}

		if (method_exists($this, 'rolesAndPermissions')) {
			$data['roles_and_permissions'] = $this->roles_and_permissions;
		}

		return $data;
	}

}