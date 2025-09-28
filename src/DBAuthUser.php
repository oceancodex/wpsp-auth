<?php

namespace WPSPCORE\Auth;

use stdClass;
use WPSPCORE\Base\BaseInstances;

class DBAuthUser extends BaseInstances {
	public stdClass $raw;

	public function afterInstanceConstruct(): void {
		$this->raw = $this->customProperties['user'];
	}

	public function id(): int {
		return (int)$this->raw->id;
	}

	public function can(string $perm): bool {
		global $wpdb; $p = \WPSP\Funcs::getDBCustomMigrationTablePrefix(); $uid=$this->id();
		$sql = $wpdb->prepare("
            SELECT 1 FROM {$p}permissions pr
            WHERE pr.name=%s AND (
                EXISTS (SELECT 1 FROM {$p}model_has_permissions mp WHERE mp.model_id=%d AND mp.permission_id=pr.id)
                OR EXISTS (SELECT 1 FROM {$p}model_has_roles mr
                           JOIN {$p}role_has_permissions rp ON rp.role_id=mr.role_id
                           WHERE mr.model_id=%d AND rp.permission_id=pr.id)
            ) LIMIT 1", $perm, $uid, $uid);
		return (bool)$wpdb->get_var($sql);
	}

	public function hasRole(string $role): bool {
		global $wpdb; $p = \WPSP\Funcs::getDBCustomMigrationTablePrefix();
		$sql = $wpdb->prepare("
            SELECT 1 FROM {$p}roles r
            WHERE r.name=%s AND EXISTS (
                SELECT 1 FROM {$p}model_has_roles mr WHERE mr.model_id=%d AND mr.role_id=r.id
            ) LIMIT 1", $role, $this->id());
		return (bool)$wpdb->get_var($sql);
	}

	public function roles(): array {
		global $wpdb; $p = \WPSP\Funcs::getDBCustomMigrationTablePrefix();
		return $wpdb->get_col($wpdb->prepare("
            SELECT r.name FROM {$p}roles r
            JOIN {$p}model_has_roles mr ON mr.role_id=r.id
            WHERE mr.model_id=%d", $this->id()));
	}

	public function permissions(): array {
		global $wpdb; $p = \WPSP\Funcs::getDBCustomMigrationTablePrefix();
		$direct = $wpdb->get_col($wpdb->prepare("
            SELECT pr.name FROM {$p}permissions pr
            JOIN {$p}model_has_permissions mp ON mp.permission_id=pr.id
            WHERE mp.model_id=%d", $this->id()));
		$via = $wpdb->get_col($wpdb->prepare("
            SELECT DISTINCT pr.name FROM {$p}permissions pr
            JOIN {$p}role_has_permissions rp ON rp.permission_id=pr.id
            JOIN {$p}model_has_roles mr ON mr.role_id=rp.role_id
            WHERE mr.model_id=%d", $this->id()));
		return array_values(array_unique(array_merge($direct ?? [], $via ?? [])));
	}

	public function assignRole(string|array $roles): void {
		// chèn vào {$p}model_has_roles theo tên role -> id
		// (tương tự givePermissionTo bên dưới)
	}

	public function givePermissionTo(string|array $perms): void {
		// chèn vào {$p}model_has_permissions theo tên permission -> id
	}
}