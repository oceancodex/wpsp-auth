<?php

namespace WPSPCORE\Auth\Providers;

use WPSPCORE\Base\BaseInstances;

class UsersProvider extends BaseInstances {

	protected string $table;

	public function afterInstanceConstruct(): void {
		$this->table = $this->funcs->_getDBCustomMigrationTableName('users');
	}

	public function retrieveById(int $id): ?\stdClass {
		global $wpdb;
		$row = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$this->table} WHERE id = %d", $id));
		return $row ?: null;
	}

	public function retrieveByCredentials(array $credentials): ?\stdClass {
		global $wpdb;

		$login = $credentials['login'] ?? null;
		if (!$login) return null;

		// Phân biệt email/username
		if (filter_var($login, FILTER_VALIDATE_EMAIL)) {
			$row = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$this->table} WHERE email = %s", $login));
		}
		else {
			$row = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$this->table} WHERE username = %s", $login));
		}

		return $row ?: null;
	}
}