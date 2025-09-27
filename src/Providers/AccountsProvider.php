<?php

namespace WPSPCORE\Auth\Providers;

use WPSP\Funcs;

/**
 * AccountsProvider: truy vấn bảng wp_wpsp_cm_accounts
 * Hỗ trợ đăng nhập bằng username hoặc email.
 */
class AccountsProvider {

	protected string $table;

	public function __construct() {
		$this->table = Funcs::getDBCustomMigrationTableName('accounts');
	}

	public function retrieveById(int $id): ?\stdClass {
		global $wpdb;
		$row = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$this->table} WHERE id = %d", $id));
		return $row ?: null;
	}

	/**
	 * credentials:
	 * - login: username hoặc email
	 * - password: mật khẩu gõ vào
	 */
	public function retrieveByCredentials(array $credentials): ?\stdClass {
		global $wpdb;

		$login = $credentials['login'] ?? null;
		if (!$login) return null;

		// Phân biệt email/username
		if (filter_var($login, FILTER_VALIDATE_EMAIL)) {
			$row = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$this->table} WHERE email = %s", $login));
		} else {
			$row = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$this->table} WHERE username = %s", $login));
		}

		return $row ?: null;
	}
}