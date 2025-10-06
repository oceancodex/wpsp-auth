<?php

namespace WPSPCORE\Auth\Traits;

trait VirtualAttributesTrait {

	/**
	 * Accessor để lấy guard_name
	 * Không map tới cột DB, chỉ là virtual attribute
	 */
	public function getGuardNameAttribute(): ?string {
		// Lấy từ attributes nếu đã được set trong Guard
		return $this->attributes['guard_name'] ?? null;
	}

	/**
	 * Accessor để lấy guard_name
	 * Không map tới cột DB, chỉ là virtual attribute
	 */
	public function getAccessTokenAttribute(): ?string {
		// Lấy từ attributes nếu đã được set trong Guard
		return $this->attributes['access_token'] ?? null;
	}

	/**
	 * Override phương thức getDirty để loại bỏ virtual attributes khỏi danh sách thay đổi
	 * Đảm bảo khi save() sẽ không cố ghi virtual attributes vào DB
	 */
	public function getDirty(): array {
		$dirty = parent::getDirty();

		// Loại bỏ virtual attributes khỏi các thay đổi cần lưu
		unset($dirty['guard_name']);
		unset($dirty['access_token']);

		return $dirty;
	}

	/**
	 * Override setAttribute để đánh dấu virtual attribute
	 */
	public function setAttribute($key, $value) {
		if ($key === 'guard_name' || $key === 'access_token') {
			$this->attributes[$key] = $value;
			return $this;
		}

		return parent::setAttribute($key, $value);
	}

}