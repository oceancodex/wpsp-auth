<?php

namespace WPSPCORE\Auth\Providers;

class WPUsersProvider {

	protected string $table;

	public function __construct(string $table = 'wp_users') {
		$this->table = $table;
	}

	public function retrieveById(int $id): ?\stdClass {
		global $wpdb;
		$row = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$this->table} WHERE ID = %d", $id));
		return $row ?: null;
	}

	public function retrieveByCredentials(array $credentials): ?\stdClass {
		global $wpdb;
		if (empty($credentials['login'])) return null;

		$row = $wpdb->get_row($wpdb->prepare(
			"SELECT * FROM {$this->table} WHERE user_login = %s",
			$credentials['login']
		));
		return $row ?: null;
	}
}