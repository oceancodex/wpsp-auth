<?php

namespace WPSPCORE\Auth\Providers;

use WPSPCORE\Base\BaseInstances;

class AuthServiceProvider extends BaseInstances {

	/** @var string|null|\MongoDB\Laravel\Eloquent\Model|\Illuminate\Database\Eloquent\Model  */
	private          $modelClass         = null;
	private ?string  $table              = null;
	protected ?array $formLoginFields    = ['login', 'email'];
	protected ?array $formPasswordFields = ['password'];
	protected ?array $dbIdFields         = ['id', 'ID'];
	protected ?array $dbLoginFields      = ['username', 'email'];
	protected ?array $dbPasswordFields   = ['password'];

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

	protected function findResultById(int $id): ?object {
		if ($this->modelClass && class_exists($this->modelClass)) {
			$model = ($this->modelClass)::query()->find($id);
			return $model ?: null;
		}
		elseif ($this->table) {
			global $wpdb;
			$whereString = '';
			if (!empty($this->dbIdFields)) {
				foreach ($this->dbIdFields as $key => $dbIdField) {
					if ($key < 1) {
						$whereString = "WHERE {$dbIdField} = %d";
					}
					else {
						$whereString .= " OR $dbIdField = %d";
					}
				}
			}
			if (!$whereString) $whereString = "WHERE ID = %d";
			$row = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$this->table} {$whereString}", $id));
			return $row ?: null;
		}
		return null;
	}

	protected function findResultByLogin(string $login): ?object {
		if ($this->modelClass && class_exists($this->modelClass)) {
			$model = ($this->modelClass)::query()
				->where(function($q) use ($login) {
					$q->where('username', $login)->orWhere('email', $login);
					if (!empty($this->dbLoginFields)) {
						foreach ($this->dbLoginFields as $dbLoginField) {
							$q->orWhere($dbLoginField, $login);
						}
					}
				})
				->first();
			return $model ?: null;
		}
		elseif ($this->table) {
			global $wpdb;
			$whereString = '';
			if (!empty($this->dbLoginFields)) {
				foreach ($this->dbLoginFields as $key => $dbLoginField) {
					if ($key < 1) {
						$whereString = "WHERE {$dbLoginField} = %s";
					}
					else {
						$whereString .= " OR $dbLoginField = %s";
					}
				}
			}
			if (!$whereString) $whereString = "WHERE user_login = %s";
			$row = $wpdb->get_row($wpdb->prepare(
				"SELECT * FROM {$this->table} {$whereString}",
				$login
			));
			return $row ?: null;
		}
		return null;
	}

	/*
	 *
	 */

	public function retrieveById(int $id) {
		return $this->findResultById($id);
	}

	public function retrieveByCredentials(array $credentials) {
		if (!empty($this->formLoginFields)) {
			foreach ($this->formLoginFields as $formLoginField) {
				if (!empty($credentials[$formLoginField])) {
					$result = $this->findResultByLogin($credentials[$formLoginField]);
					if ($result) return $result;
				}
			}
		}
		return null;
	}

}