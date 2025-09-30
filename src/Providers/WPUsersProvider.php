<?php

namespace WPSPCORE\Auth\Providers;

use WPSPCORE\Base\BaseInstances;

class WPUsersProvider extends BaseInstances {

	protected string $table;

	public function afterInstanceConstruct() {
		$this->table = $this->customProperties['table'];
	}

	public function retrieveById(int $id) {
		global $wpdb;
		$row = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$this->table} WHERE ID = %d", $id));
		return $row ?: null;
	}

	public function retrieveByCredentials(array $credentials) {
		global $wpdb;
		if (empty($credentials['login'])) return null;

		$row = $wpdb->get_row($wpdb->prepare(
			"SELECT * FROM {$this->table} WHERE user_login = %s",
			$credentials['login']
		));
		return $row ?: null;
	}
}