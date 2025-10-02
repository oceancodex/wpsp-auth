<?php

namespace WPSPCORE\Auth\Guards;

use WPSPCORE\Auth\Drivers\Database\User;
use WPSPCORE\Auth\Providers\AuthServiceProvider;
use WPSPCORE\Base\BaseInstances;
use WPSPCORE\Permission\Traits\PermissionTrait;
use function MongoDB\object;

class TokensGuard extends BaseInstances {

	protected AuthServiceProvider $provider;
	protected string              $guardName;

	// Cache theo request
	protected ?User    $DBAuthUser    = null;
	protected ?object  $cachedRawUser = null;
	protected ?string  $cachedToken   = null;

	/*
	 *
	 */

	public function afterInstanceConstruct(): void {
		$this->provider      = $this->customProperties['provider'];
		$this->guardName     = $this->customProperties['guard_name'] ?? 'api';
	}

	/*
	 *
	 */

	public function attempt(array $credentials): bool {
		$user = $this->provider->retrieveByCredentials($credentials);
		if (!$user) return false;

		foreach ($this->provider->dbPasswordFields as $dbPasswordField) {
			foreach ($this->provider->formPasswordFields as $formPasswordField) {
				$given  = $credentials[$formPasswordField] ?? null;
				$hashed = $user->{$dbPasswordField} ?? null;
				if ($given !== null && $hashed && wp_check_password($given, $hashed)) {
					// Không tạo session; cache kết quả cho lần gọi hiện tại
					$this->cachedRawUser = $user instanceof \stdClass ? $user : (is_array($user) ? object($user): $user);
					return true;
				}
			}
		}
		return false;
	}

	/*
	 *
	 */

	/**
	 * @return array|\Illuminate\Database\Eloquent\Model|object|\stdClass|null|PermissionTrait
	 */
	public function user() {
		$raw = $this->rawUserFromToken();
		if (!$raw) return null;

		// Set guard_name
		$raw->guard_name = $this->guardName;

		// Chuẩn hóa thành DBAuthUser dùng PermissionTrait
		if ($raw instanceof \stdClass) {
			if (!($this->DBAuthUser instanceof User) || $this->DBAuthUser->raw !== $raw) {
				$this->DBAuthUser = new User(
					$this->funcs->_getMainPath(),
					$this->funcs->_getRootNamespace(),
					$this->funcs->_getPrefixEnv(),
					['user' => $raw]
				);
			}
			return $this->DBAuthUser;
		}

		return $raw;
	}

	public function check(): bool {
		return $this->id() !== null;
	}

	public function id(): ?int {
		$raw = $this->rawUserFromToken();
		if (!$raw) return null;

		foreach ($this->provider->dbIdFields as $dbIdField) {
			try {
				$id = $raw->{$dbIdField} ?? null;
			}
			catch (\Throwable $e) {
				continue;
			}
			if ($id) return (int)$id;
		}
		return null;
	}

	public function logout(): void {
		// Stateless: chỉ xóa cache
		$this->cachedToken   = null;
		$this->cachedRawUser = null;
		$this->DBAuthUser    = null;
	}

	public function getProvider() {
		return $this->provider;
	}

	/*
	 * Helpers
	 */

	protected function bearerToken(): ?string {
		// Cache token theo request để tránh parse header nhiều lần
		if ($this->cachedToken !== null) {
			return $this->cachedToken ?: null;
		}

		$header = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['Authorization'] ?? null;
		if (!$header && function_exists('apache_request_headers')) {
			$headers = getallheaders();
			// Chuẩn hóa key không phân biệt hoa thường
			foreach ($headers as $k => $v) {
				if (strcasecmp($k, 'Authorization') === 0) {
					$header = $v;
					break;
				}
			}
		}

		$token = null;
		if ($header && preg_match('/Bearer\s+(.+)/i', $header, $m)) {
			$token = trim($m[1]);
		}

		// Hỗ trợ query param và body (tùy tình huống)
		if (!$token) {
			$token = $_GET['api_token'] ?? $_GET['access_token'] ?? $_POST['api_token'] ?? $_POST['access_token'] ?? null;
			if (is_string($token)) $token = trim($token);
		}

		$this->cachedToken = $token ?: '';
		return $token ?: null;
	}

	protected function rawUserFromToken(): ?object {
		// Nếu đã cache user cho token hiện tại thì dùng lại
		$incomingToken = $this->bearerToken();
		if (!$incomingToken) return null;

		if ($this->cachedRawUser instanceof \stdClass && $this->cachedToken === $incomingToken) {
			return $this->cachedRawUser;
		}

		// Ưu tiên provider eloquent nếu có model
		$modelClass = $this->getProviderModelClass();
		if ($modelClass && class_exists($modelClass)) {
			/** @var \Illuminate\Database\Eloquent\Builder $query */
			$query = ($modelClass)::query();
			$query->where(function($q) use ($incomingToken) {
				foreach ($this->provider->dbTokenFields as $f) {
					$q->orWhere($f, $incomingToken);
				}
			});
			$found = $query->first();
			if ($found) {
				// Tránh dùng getAttributes trực tiếp nếu model có casts; cast sang stdClass an toàn
				$this->cachedRawUser = (object) $found->toArray();
				$this->cachedToken   = $incomingToken;
				return $this->cachedRawUser;
			}
			return null;
		}

		// Fallback provider dạng table
		$table = $this->getProviderTable();
		if ($table) {
			global $wpdb;
			$wheres = [];
			$args   = [];
			foreach ($this->provider->dbTokenFields as $f) {
				$wheres[] = "{$f} = %s";
				$args[]   = $incomingToken;
			}
			if ($wheres) {
				$whereSql = 'WHERE (' . implode(' OR ', $wheres) . ')';
				$row = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$table} {$whereSql}", ...$args));
				if ($row) {
					$this->cachedRawUser = $row;
					$this->cachedToken   = $incomingToken;
					return $row;
				}
			}
		}

		return null;
	}

	// Tránh reflection tốn kém: thêm getter nội bộ an toàn
	protected function getProviderModelClass(): ?string {
		// AuthServiceProvider đã nhận modelClass qua options['model_class']
		// Dùng method công khai nếu có, nếu không dùng property nếu public/protected (tránh reflection)
		if (method_exists($this->provider, 'getModelClass')) {
			return $this->provider->getModelClass();
		}
		// Provider hiện tại dùng thuộc tính private, nhưng ta cố gắng tránh reflection:
		// cho phép truyền model_class từ customProperties guard nếu có
		$override = $this->customProperties['model_class'] ?? null;
		return is_string($override) ? $override : null;
	}

	protected function getProviderTable(): ?string {
		if (method_exists($this->provider, 'getTable')) {
			return $this->provider->getTable();
		}
		return $this->customProperties['table'] ?? null;
	}

}