<?php

namespace WPSPCORE\Auth\Providers;

use WPSPCORE\Base\BaseInstances;

class AuthServiceProvider extends BaseInstances {

	/** @var string|null|\MongoDB\Laravel\Eloquent\Model|\Illuminate\Database\Eloquent\Model */
	public $modelClass         = null;
	public $table              = null;
	public $formLoginFields    = ['login'];
	public $formPasswordFields = ['password'];
	public $dbIdFields         = ['id'];
	public $dbLoginFields      = ['username', 'email'];
	public $dbPasswordFields   = ['password'];
	public $dbTokenFields      = ['api_token'];

	/*
	 *
	 */

	public function afterInstanceConstruct() {
		$this->table      = $this->extraParams['table'];
		$this->modelClass = $this->extraParams['model_class'] ?? null;
	}

	/*
	 *
	 */

	public function findResultById($id) {
		if ($this->modelClass && class_exists($this->modelClass)) {
			/** @var \Illuminate\Database\Eloquent\Builder $query */
			$query = ($this->modelClass)::query();

			if (!empty($this->dbIdFields)) {
				$query->where(function($q) use ($id) {
					foreach ($this->dbIdFields as $dbIdField) {
						$q->orWhere($dbIdField, $id);
					}
				});
			}
			else {
				$query->where('id', $id);
			}

			$model = $query->get()->first();

			return $model ?: null;
		}
		elseif ($this->table) {
			global $wpdb;
			$whereString = '';
			$prepareArgs = [$id];

			if (!empty($this->dbIdFields)) {
				foreach ($this->dbIdFields as $key => $dbIdField) {
					if ($key < 1) {
						$whereString = "WHERE {$dbIdField} = %d";
					}
					else {
						$whereString   .= " OR {$dbIdField} = %d";
						$prepareArgs[] = $id; // Thêm tham số cho mỗi OR
					}
				}
			}

			if (!$whereString) {
				$whereString = "WHERE id = %d";
			}

			// Truyền tất cả tham số vào prepare
			$row = $wpdb->get_row($wpdb->prepare(
				"SELECT * FROM {$this->table} {$whereString}",
				...$prepareArgs
			));
			return $row ?: null;
		}
		return null;
	}

	public function findResultByLogin($login) {
		// Eloquent.
		if ($this->modelClass && class_exists($this->modelClass)) {
			/** @var \Illuminate\Database\Eloquent\Builder $query */
			$query = ($this->modelClass)::query();

			if (!empty($this->dbLoginFields)) {
				$query->where(function($q) use ($login) {
					foreach ($this->dbLoginFields as $dbLoginField) {
						$q->orWhere($dbLoginField, $login);
					}
				});
			}
			else {
				$query->where('username', $login);
			}

			$model = $query->get()->first();

			return $model ?: null;
		}

		// WordPress "$wpdb".
		elseif ($this->table) {
			global $wpdb;
			$whereString = '';
			$prepareArgs = [$login];

			if (!empty($this->dbLoginFields)) {
				foreach ($this->dbLoginFields as $key => $dbLoginField) {
					if ($key < 1) {
						$whereString = "WHERE {$dbLoginField} = %s";
					}
					else {
						$whereString   .= " OR {$dbLoginField} = %s";
						$prepareArgs[] = $login; // Thêm tham số cho mỗi OR
					}
				}
			}

			if (!$whereString) {
				$whereString = "WHERE username = %s";
			}

			// Truyền tất cả tham số vào prepare
			$row = $wpdb->get_row($wpdb->prepare(
				"SELECT * FROM {$this->table} {$whereString}",
				...$prepareArgs
			));
			return $row ?: null;
		}

		return null;
	}

	/*
	 *
	 */

	public function retrieveById($id) {
		return $this->findResultById($id);
	}

	public function retrieveByToken($token = null) {
		if (!$token) return null;
		if ($this->modelClass && class_exists($this->modelClass)) {
			/** @var \Illuminate\Database\Eloquent\Builder $query */
			$query = ($this->modelClass)::query();

			if (!empty($this->dbTokenFields)) {
				$query->where(function($q) use ($token) {
					foreach ($this->dbTokenFields as $dbTokenField) {
						$q->orWhere($dbTokenField, $token);
					}
				});
			}
			else {
				$query->where('api_token', $token);
			}

			$model = $query->get()->first();

			return $model ?: null;
		}
		elseif ($this->table) {
			global $wpdb;
			$whereString = '';
			$prepareArgs = [$token];

			if (!empty($this->dbTokenFields)) {
				foreach ($this->dbTokenFields as $key => $dbTokenField) {
					if ($key < 1) {
						$whereString = "WHERE {$dbTokenField} = %s";
					}
					else {
						$whereString   .= " OR {$dbTokenField} = %s";
						$prepareArgs[] = $token; // Thêm tham số cho mỗi OR
					}
				}
			}

			if (!$whereString) {
				$whereString = "WHERE api_token = %s";
			}

			// Truyền tất cả tham số vào prepare
			$row = $wpdb->get_row($wpdb->prepare(
				"SELECT * FROM {$this->table} {$whereString}",
				...$prepareArgs
			));
			return $row ?: null;
		}
		return null;
	}

	public function retrieveByAccessToken($token) {}

	public function retrieveByCredentials($credentials) {
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

	/**
	 * @param string[] $formPasswordFields
	 *
	 * @return AuthServiceProvider
	 */
	public function setFormPasswordFields($formPasswordFields) {
		$this->formPasswordFields = $formPasswordFields;
		return $this;
	}

}