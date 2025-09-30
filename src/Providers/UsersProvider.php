<?php

namespace WPSPCORE\Auth\Providers;

use WPSPCORE\Base\BaseInstances;

class UsersProvider extends BaseInstances {

	protected string $table;

	protected ?string $modelClass = null;

	/*
	 *
	 */

	public function afterInstanceConstruct() {
		$this->table      = $this->customProperties['table'];
		$this->modelClass = $this->customProperties['options']['model_class'] ?? null;
	}

	/*
	 *
	 */

	protected function findModelById(int $id): ?object {
		if ($this->modelClass && class_exists($this->modelClass)) {
			$model = ($this->modelClass)::query()->find($id);
			return $model ?: null;
		}
		return null;
	}

	protected function findModelByLogin(string $login): ?object {
		if ($this->modelClass && class_exists($this->modelClass)) {
			$model = ($this->modelClass)::query()
				->where(function($q) use ($login) {
					$q->where('username', $login)->orWhere('email', $login);
				})
				->first();
			return $model ?: null;
		}
		return null;
	}

	/*
	 *
	 */

	public function retrieveById(int $id) {
		// Nếu có modelClass thì trả về Eloquent model (có trait HasRoles -> có can())
		$model = $this->findModelById($id);
		if ($model) return $model;

		// Fallback stdClass từ bảng WP mặc định
		global $wpdb;
		$row = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$this->table} WHERE ID = %d", $id));
		return $row ?: null;
	}

	public function retrieveByCredentials(array $credentials) {
		// Nếu có modelClass thì trả về Eloquent model
		if (!empty($credentials['login'])) {
			$model = $this->findModelByLogin($credentials['login']);
			if ($model) return $model;
		}
	}
}