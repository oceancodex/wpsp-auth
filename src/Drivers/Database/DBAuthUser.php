<?php

namespace WPSPCORE\Auth\Drivers\Database;

use WPSPCORE\Base\BaseInstances;
use WPSPCORE\Permission\Traits\DBPermissionTrait;
use WPSPCORE\Sanctum\Traits\DBSanctumTokensTrait;

class DBAuthUser extends BaseInstances {

	use DBPermissionTrait, DBSanctumTokensTrait;

	public $guardName;
	public $rawUser;
	public $roles;
	public $permissions;
	public $rolesAndPermissions;

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

	/**
	 * Magic method to set properties on rawUser
	 */
	public function __set($name, $value) {
		if (is_object($this->rawUser)) {
			$this->rawUser->$name = $value;
		}
	}

	/**
	 * Magic method to get properties from rawUser
	 */
	public function __get($name) {
		if (is_object($this->rawUser)) {
			return $this->rawUser->$name ?? null;
		}
		return null;
	}

	/**
	 * Magic method to check if property exists on rawUser
	 */
	public function __isset($name) {
		if (is_object($this->rawUser)) {
			return isset($this->rawUser->$name);
		}
		return false;
	}

	/**
	 * Save the user to database
	 *
	 * @return bool
	 */
	public function save(): bool {
		global $wpdb;

		if (!$this->rawUser) {
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

		// Convert rawUser to array for update
		$data = is_object($this->rawUser) ? get_object_vars($this->rawUser) : (array)$this->rawUser;

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

	/**
	 * Get table name from auth configuration
	 *
	 * @return string|null
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