<?php

namespace WPSPCORE\Auth\Traits;

trait GuardNameTrait {

	/**
	 * Accessor để lấy guard_name
	 * Không map tới cột DB, chỉ là virtual attribute
	 */
	public function getGuardNameAttribute(): ?string {
		// Lấy từ attributes nếu đã được set trong Guard
		return $this->attributes['guard_name'] ?? null;
	}

	/**
	 * Override phương thức getDirty để loại bỏ guard_name khỏi danh sách thay đổi
	 * Đảm bảo khi save() sẽ không cố ghi guard_name vào DB
	 */
	public function getDirty(): array {
		$dirty = parent::getDirty();

		// Loại bỏ guard_name khỏi các thay đổi cần lưu
		unset($dirty['guard_name']);

		return $dirty;
	}

	/**
	 * Override setAttribute để đánh dấu guard_name là virtual attribute
	 */
	public function setAttribute($key, $value) {
		// Nếu là guard_name, chỉ lưu vào attributes không đánh dấu là dirty
		if ($key === 'guard_name') {
			$this->attributes[$key] = $value;
			return $this;
		}

		return parent::setAttribute($key, $value);
	}

}