<?php

namespace WPSPCORE\Auth\Models;

use WPSPCORE\Base\BaseInstances;
use WPSPCORE\Permission\Traits\DBPermissionTrait;
use WPSPCORE\Sanctum\Traits\DBSanctumTokensTrait;

class DBAuthUserModel extends BaseInstances {

	use DBPermissionTrait, DBSanctumTokensTrait;

	public $guardName;
	public $authUser;
	public $roles;
	public $permissions;
	public $rolesAndPermissions;

	public function afterInstanceConstruct(): void {
		$this->guardName            = $this->customProperties['guard_name'];
		$this->authUser             = $this->customProperties['auth_user'];
		$this->authUser->guard_name = $this->guardName;
//		$this->roles               = $this->roles();
//		$this->permissions         = $this->permissions();
//		$this->rolesAndPermissions = $this->rolesAndPermissions();
	}

	/*
	 *
	 */

	public function __set($name, $value) {
		if (is_object($this->authUser)) {
			$this->authUser->$name = $value;
		}
	}

	public function __get($name) {
		if (is_object($this->authUser)) {
			return $this->authUser->$name ?? null;
		}
		return null;
	}

	public function __isset($name) {
		if (is_object($this->authUser)) {
			return isset($this->authUser->$name);
		}
		return false;
	}

	/*
	 *
	 */

	public function id(): int {
		return $this->authUser->id ?? ($this->authUser->ID ?? 0);
	}

	public function save(): bool {
		global $wpdb;

		if (!$this->authUser) {
			return false;
		}

		$userId = $this->id();
		if (!$userId) {
			return false;
		}

		// Get the table name from the guard configuration
		$tableName = $this->getTableName();
		if (!$tableName) {
			return false;
		}

		// Convert authUser to array for update
		$data = is_object($this->authUser) ? get_object_vars($this->authUser) : (array)$this->authUser;

		// Remove properties that shouldn't be saved
		unset($data['guard_name']);
		unset($data['id']);
		unset($data['ID']);

		// Prepare update data
		$updateData = [];
		$format = [];

		foreach ($data as $key => $value) {
			$updateData[$key] = $value;
			$format[] = is_numeric($value) ? '%d' : '%s';
		}

		if (empty($updateData)) {
			return false;
		}

		// Update the database
		$result = $wpdb->update(
			$tableName,
			$updateData,
			['id' => $userId],
			$format,
			['%d']
		);

		return $result !== false;
	}

	/*
	 *
	 */


	public function toArray(): array {
		$data = is_object($this->authUser) ? get_object_vars($this->authUser) : (array)$this->authUser;

//		$data['roles']                 = $this->roles;
//		$data['permissions']           = $this->permissions;
//		$data['roles_and_permissions'] = $this->rolesAndPermissions;

		return $data;
	}

	/*
	 *
	 */

	private function getTableName(): ?string {
		// Get auth configuration
		$authConfig = $this->funcs->_config('auth');

		if (!$authConfig || !isset($authConfig['guards'][$this->guardName])) {
			return null;
		}

		$guard = $authConfig['guards'][$this->guardName];
		$providerName = $guard['provider'] ?? null;

		if (!$providerName || !isset($authConfig['providers'][$providerName])) {
			return null;
		}

		$provider = $authConfig['providers'][$providerName];

		// Return table name if it's a database provider
		if ($provider['driver'] === 'database' && isset($provider['table'])) {
			return $provider['table'];
		}

		return null;
	}
}