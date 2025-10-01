<?php

namespace WPSPCORE\Auth\Drivers\Database;

use WPSPCORE\Base\BaseInstances;
use WPSPCORE\Permission\Collections\RolesCollection;
use WPSPCORE\Permission\Traits\DBPermissionTrait;

class User extends BaseInstances {

	use DBPermissionTrait;

	public $raw;
	public $roles;
	public $permissions;

	public function afterInstanceConstruct(): void {
		$this->raw = $this->customProperties['user'];

		if (method_exists($this, 'roles')) {
			$this->roles = new RolesCollection($this->roles(), $this);
		}

		if (method_exists($this, 'permissions')) {
			$this->permissions = $this->permissions();
		}
	}

	public function id(): int {
		return (int)$this->raw->id;
	}

	public function toArray(): array {
		$data = is_object($this->raw) ? get_object_vars($this->raw) : (array)$this->raw;

		$data['id']    = $this->id();
		$data['roles'] = $this->roles->toArray();

		if (method_exists($this, 'permissions')) {
			$data['permissions'] = $this->permissions;
		}

		return $data;
	}

}