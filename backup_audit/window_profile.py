from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .models import BackupWindow
from .waiver import get_global_config_dir


WINDOW_PROFILES_FILENAME = "window_profiles.json"
WINDOW_PROFILE_LOG_FILENAME = "window_profile_audit_log.json"
WINDOW_PROFILE_APPLICATIONS_FILENAME = "window_profile_applications.json"
WINDOW_PROFILE_SNAPSHOTS_DIRNAME = "window_profile_snapshots"

_TIMEZONE_PATTERN = re.compile(r"^[+-]\d{2}:\d{2}$|^UTC$|^Z$")


class WindowProfileAction(str, Enum):
    CREATE = "window_profile_create"
    UPDATE = "window_profile_update"
    DELETE = "window_profile_delete"
    APPLY = "window_profile_apply"
    IMPORT = "window_profile_import"
    EXPORT = "window_profile_export"
    SHOW = "window_profile_show"


class WindowProfileValidationError(Exception):
    pass


class WindowProfileConflictError(Exception):
    pass


class WindowProfileNotFoundError(Exception):
    pass


class WindowProfileModifiedError(Exception):
    pass


class WindowProfileAlreadyAppliedError(Exception):
    pass


@dataclass
class WindowProfile:
    name: str
    window_start: str
    window_end: str
    timezone: str
    business_lines: List[str]
    notes: str = ""
    actor: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    version: int = 1
    active: bool = True

    @classmethod
    def create(
        cls,
        name: str,
        window_start: str,
        window_end: str,
        timezone: str,
        business_lines: List[str],
        notes: str = "",
        actor: str = "",
    ) -> "WindowProfile":
        return cls(
            name=name,
            window_start=window_start,
            window_end=window_end,
            timezone=timezone,
            business_lines=business_lines or [],
            notes=notes,
            actor=actor,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WindowProfile":
        return cls(
            name=data["name"],
            window_start=data["window_start"],
            window_end=data["window_end"],
            timezone=data["timezone"],
            business_lines=data.get("business_lines", []),
            notes=data.get("notes", ""),
            actor=data.get("actor", ""),
            created_at=data.get("created_at", datetime.now().isoformat()),
            updated_at=data.get("updated_at", datetime.now().isoformat()),
            version=data.get("version", 1),
            active=data.get("active", True),
        )

    def fingerprint(self) -> str:
        raw = (
            f"{self.name}|{self.window_start}|{self.window_end}|"
            f"{self.timezone}|{','.join(sorted(self.business_lines))}|{self.version}"
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_backup_window(self) -> BackupWindow:
        return BackupWindow(
            start=self.window_start,
            end=self.window_end,
        )


@dataclass
class WindowProfileSnapshot:
    profile_name: str
    profile_version: int
    window_start: str
    window_end: str
    timezone: str
    business_lines: List[str]
    notes: str
    applied_at: str
    applied_by: str
    batch_id: str
    profile_fingerprint: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WindowProfileSnapshot":
        return cls(
            profile_name=data["profile_name"],
            profile_version=data["profile_version"],
            window_start=data["window_start"],
            window_end=data["window_end"],
            timezone=data["timezone"],
            business_lines=data.get("business_lines", []),
            notes=data.get("notes", ""),
            applied_at=data["applied_at"],
            applied_by=data["applied_by"],
            batch_id=data["batch_id"],
            profile_fingerprint=data["profile_fingerprint"],
        )

    def to_backup_window(self) -> BackupWindow:
        return BackupWindow(
            start=self.window_start,
            end=self.window_end,
        )


@dataclass
class WindowProfileApplicationRecord:
    profile_name: str
    profile_version: int
    batch_id: str
    applied_at: str
    applied_by: str
    profile_fingerprint: str
    backup_dir: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WindowProfileApplicationRecord":
        return cls(
            profile_name=data["profile_name"],
            profile_version=data["profile_version"],
            batch_id=data["batch_id"],
            applied_at=data["applied_at"],
            applied_by=data["applied_by"],
            profile_fingerprint=data["profile_fingerprint"],
            backup_dir=data.get("backup_dir", ""),
        )


@dataclass
class WindowProfileAuditLogEntry:
    action: WindowProfileAction
    actor: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    profile_name: Optional[str] = None
    batch_id: Optional[str] = None
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action.value,
            "actor": self.actor,
            "timestamp": self.timestamp,
            "profile_name": self.profile_name,
            "batch_id": self.batch_id,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WindowProfileAuditLogEntry":
        return cls(
            action=WindowProfileAction(data["action"]),
            actor=data.get("actor", ""),
            timestamp=data.get("timestamp", datetime.now().isoformat()),
            profile_name=data.get("profile_name"),
            batch_id=data.get("batch_id"),
            detail=data.get("detail", {}),
        )


@dataclass
class WindowProfileExportBundle:
    version: int = 1
    exported_at: str = field(default_factory=lambda: datetime.now().isoformat())
    profiles: List[WindowProfile] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "exported_at": self.exported_at,
            "profiles": [p.to_dict() for p in self.profiles],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WindowProfileExportBundle":
        return cls(
            version=data.get("version", 1),
            exported_at=data.get("exported_at", datetime.now().isoformat()),
            profiles=[WindowProfile.from_dict(p) for p in data.get("profiles", [])],
        )


def validate_timezone(tz: str) -> Tuple[bool, str]:
    if not tz:
        return False, "时区不能为空"
    if not _TIMEZONE_PATTERN.match(tz):
        return False, f"时区格式无效: '{tz}'。必须为 UTC、Z 或 ±HH:MM 格式（如 +08:00、-05:00）"
    if tz in ("UTC", "Z"):
        return True, ""
    try:
        sign = 1 if tz[0] == "+" else -1
        hh = int(tz[1:3])
        mm = int(tz[4:6])
    except (ValueError, IndexError):
        return False, f"时区解析失败: '{tz}'"
    if mm < 0 or mm > 59:
        return False, f"时区分钟部分无效: '{tz}'。分钟必须在 00-59 之间"
    total_minutes = sign * (hh * 60 + mm)
    if total_minutes < -12 * 60 or total_minutes > 14 * 60:
        return False, f"时区偏移超出合理范围: '{tz}'。必须在 -12:00 到 +14:00 之间"
    return True, ""


def validate_window_times(start: str, end: str) -> Tuple[bool, str]:
    try:
        s = datetime.fromisoformat(start)
        e = datetime.fromisoformat(end)
    except ValueError as ex:
        return False, f"时间格式无效: {ex}。必须使用 ISO 8601 格式（如 2024-01-01T00:00:00）"
    if s >= e:
        return False, "窗口起始时间必须早于结束时间"
    return True, ""


def validate_business_lines(lines: List[str], valid_lines: Optional[List[str]] = None) -> Tuple[bool, str]:
    if not lines:
        return False, "业务线列表不能为空"
    seen = set()
    for bl in lines:
        if not bl or not bl.strip():
            return False, "业务线名称不能为空"
        if bl in seen:
            return False, f"业务线重复: '{bl}'"
        seen.add(bl)
    if valid_lines is not None:
        invalid = [bl for bl in lines if bl not in valid_lines]
        if invalid:
            return False, f"业务线未在配置中声明: {', '.join(invalid)}。有效值: {', '.join(valid_lines)}"
    return True, ""


def get_window_profiles_path() -> str:
    override = os.environ.get("BACKUP_AUDIT_WINDOW_PROFILES")
    if override:
        return os.path.abspath(override)
    return os.path.join(get_global_config_dir(), WINDOW_PROFILES_FILENAME)


def get_window_profile_log_path() -> str:
    override = os.environ.get("BACKUP_AUDIT_WINDOW_PROFILE_LOG")
    if override:
        return os.path.abspath(override)
    return os.path.join(get_global_config_dir(), WINDOW_PROFILE_LOG_FILENAME)


def get_window_profile_applications_path() -> str:
    override = os.environ.get("BACKUP_AUDIT_WINDOW_PROFILE_APPLICATIONS")
    if override:
        return os.path.abspath(override)
    return os.path.join(get_global_config_dir(), WINDOW_PROFILE_APPLICATIONS_FILENAME)


def get_window_profile_snapshots_dir() -> str:
    override = os.environ.get("BACKUP_AUDIT_WINDOW_PROFILE_SNAPSHOTS")
    if override:
        return os.path.abspath(override)
    return os.path.join(get_global_config_dir(), WINDOW_PROFILE_SNAPSHOTS_DIRNAME)


def get_snapshot_path(batch_id: str) -> str:
    safe_id = batch_id.replace("/", "_").replace("\\", "_").replace("..", "_")
    return os.path.join(get_window_profile_snapshots_dir(), f"snapshot_{safe_id}.json")


class WindowProfileStore:
    def __init__(
        self,
        profiles_path: Optional[str] = None,
        log_path: Optional[str] = None,
        applications_path: Optional[str] = None,
        snapshots_dir: Optional[str] = None,
    ):
        self.profiles_path = profiles_path or get_window_profiles_path()
        self.log_path = log_path or get_window_profile_log_path()
        self.applications_path = applications_path or get_window_profile_applications_path()
        self.snapshots_dir = snapshots_dir or get_window_profile_snapshots_dir()
        self.profiles: List[WindowProfile] = []
        self.audit_log: List[WindowProfileAuditLogEntry] = []
        self.applications: List[WindowProfileApplicationRecord] = []
        self._load()

    def _load(self) -> None:
        os.makedirs(os.path.dirname(self.profiles_path), exist_ok=True)
        os.makedirs(self.snapshots_dir, exist_ok=True)

        if os.path.exists(self.profiles_path):
            try:
                with open(self.profiles_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.profiles = [WindowProfile.from_dict(p) for p in data.get("profiles", [])]
            except (json.JSONDecodeError, KeyError):
                self.profiles = []

        if os.path.exists(self.log_path):
            try:
                with open(self.log_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.audit_log = [WindowProfileAuditLogEntry.from_dict(e) for e in data.get("log", [])]
            except (json.JSONDecodeError, KeyError):
                self.audit_log = []

        if os.path.exists(self.applications_path):
            try:
                with open(self.applications_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.applications = [WindowProfileApplicationRecord.from_dict(r) for r in data.get("applications", [])]
            except (json.JSONDecodeError, KeyError):
                self.applications = []

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self.profiles_path), exist_ok=True)
        with open(self.profiles_path, "w", encoding="utf-8") as f:
            json.dump(
                {"profiles": [p.to_dict() for p in self.profiles]},
                f,
                ensure_ascii=False,
                indent=2,
            )
        with open(self.log_path, "w", encoding="utf-8") as f:
            json.dump(
                {"log": [e.to_dict() for e in self.audit_log]},
                f,
                ensure_ascii=False,
                indent=2,
            )
        with open(self.applications_path, "w", encoding="utf-8") as f:
            json.dump(
                {"applications": [r.to_dict() for r in self.applications]},
                f,
                ensure_ascii=False,
                indent=2,
            )

    def _log_operation(
        self,
        action: WindowProfileAction,
        actor: str,
        profile_name: Optional[str] = None,
        batch_id: Optional[str] = None,
        detail: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.audit_log.append(WindowProfileAuditLogEntry(
            action=action,
            actor=actor,
            profile_name=profile_name,
            batch_id=batch_id,
            detail=detail or {},
        ))

    def validate_profile(
        self,
        profile: WindowProfile,
        valid_business_lines: Optional[List[str]] = None,
    ) -> None:
        if not profile.name or not profile.name.strip():
            raise WindowProfileValidationError("模板名称不能为空 (字段: name, 值: 空)")
        if len(profile.name) > 100:
            raise WindowProfileValidationError(
                f"模板名称不能超过 100 个字符 (模板: '{profile.name}', 字段: name, 值长度: {len(profile.name)})"
            )

        ok, msg = validate_timezone(profile.timezone)
        if not ok:
            raise WindowProfileValidationError(
                f"{msg} (模板: '{profile.name}', 字段: timezone, 值: '{profile.timezone}')"
            )

        ok, msg = validate_window_times(profile.window_start, profile.window_end)
        if not ok:
            raise WindowProfileValidationError(
                f"{msg} (模板: '{profile.name}', 字段: window_start/window_end, "
                f"值: start='{profile.window_start}', end='{profile.window_end}')"
            )

        ok, msg = validate_business_lines(profile.business_lines, valid_business_lines)
        if not ok:
            raise WindowProfileValidationError(
                f"{msg} (模板: '{profile.name}', 字段: business_lines, 值: {profile.business_lines})"
            )

    def get_profile(self, name: str) -> Optional[WindowProfile]:
        for p in self.profiles:
            if p.name == name and p.active:
                return p
        return None

    def get_profile_including_inactive(self, name: str) -> Optional[WindowProfile]:
        for p in self.profiles:
            if p.name == name:
                return p
        return None

    def list_profiles(self, include_inactive: bool = False) -> List[WindowProfile]:
        if include_inactive:
            return list(self.profiles)
        return [p for p in self.profiles if p.active]

    def create_profile(
        self,
        profile: WindowProfile,
        actor: str,
        valid_business_lines: Optional[List[str]] = None,
    ) -> WindowProfile:
        if not actor or not actor.strip():
            raise WindowProfileValidationError("必须指定操作人 actor")

        self.validate_profile(profile, valid_business_lines)

        existing = self.get_profile_including_inactive(profile.name)
        if existing is not None:
            if existing.active:
                raise WindowProfileConflictError(
                    f"模板名称已存在: '{profile.name}'。请使用其他名称，或使用 update 命令更新现有模板。"
                )
            else:
                raise WindowProfileConflictError(
                    f"模板名称已被已删除的模板占用: '{profile.name}'。请使用其他名称。"
                )

        profile.actor = actor
        profile.created_at = datetime.now().isoformat()
        profile.updated_at = profile.created_at
        profile.version = 1
        profile.active = True

        self.profiles.append(profile)
        self._log_operation(
            action=WindowProfileAction.CREATE,
            actor=actor,
            profile_name=profile.name,
            detail={
                "profile": profile.to_dict(),
            },
        )
        self._save()
        return profile

    def update_profile(
        self,
        name: str,
        actor: str,
        window_start: Optional[str] = None,
        window_end: Optional[str] = None,
        timezone: Optional[str] = None,
        business_lines: Optional[List[str]] = None,
        notes: Optional[str] = None,
        valid_business_lines: Optional[List[str]] = None,
    ) -> WindowProfile:
        if not actor or not actor.strip():
            raise WindowProfileValidationError("必须指定操作人 actor")

        profile = self.get_profile(name)
        if profile is None:
            raise WindowProfileNotFoundError(f"模板不存在: '{name}'")

        updated = WindowProfile.from_dict(profile.to_dict())
        if window_start is not None:
            updated.window_start = window_start
        if window_end is not None:
            updated.window_end = window_end
        if timezone is not None:
            updated.timezone = timezone
        if business_lines is not None:
            updated.business_lines = business_lines
        if notes is not None:
            updated.notes = notes

        self.validate_profile(updated, valid_business_lines)

        updated.version += 1
        updated.updated_at = datetime.now().isoformat()
        updated.actor = actor

        for i, p in enumerate(self.profiles):
            if p.name == name:
                self.profiles[i] = updated
                break

        self._log_operation(
            action=WindowProfileAction.UPDATE,
            actor=actor,
            profile_name=name,
            detail={
                "old_version": profile.version,
                "new_version": updated.version,
                "old_profile": profile.to_dict(),
                "new_profile": updated.to_dict(),
            },
        )
        self._save()
        return updated

    def delete_profile(self, name: str, actor: str) -> bool:
        if not actor or not actor.strip():
            raise WindowProfileValidationError("必须指定操作人 actor")

        profile = self.get_profile(name)
        if profile is None:
            raise WindowProfileNotFoundError(f"模板不存在: '{name}'")

        profile.active = False
        profile.updated_at = datetime.now().isoformat()

        self._log_operation(
            action=WindowProfileAction.DELETE,
            actor=actor,
            profile_name=name,
            detail={
                "deleted_profile": profile.to_dict(),
            },
        )
        self._save()
        return True

    def check_profile_modified(self, profile: WindowProfile, expected_fingerprint: str) -> None:
        if profile.fingerprint() != expected_fingerprint:
            raise WindowProfileModifiedError(
                f"模板 '{profile.name}' 自上次应用后已被修改（版本 {profile.version}）。"
                f"请重新确认模板内容后再操作，或使用 --force 强制使用当前版本。"
            )

    def check_already_applied(self, profile_name: str, batch_id: str) -> None:
        for app in self.applications:
            if app.profile_name == profile_name and app.batch_id == batch_id:
                raise WindowProfileAlreadyAppliedError(
                    f"模板 '{profile_name}' 已应用于批次 '{batch_id}'（应用时间: {app.applied_at}）。"
                    f"同一批次不能重复套用同一模板。"
                )

    def apply_to_batch(
        self,
        profile_name: str,
        batch_id: str,
        backup_dir: str,
        actor: str,
        expected_fingerprint: Optional[str] = None,
        force: bool = False,
        valid_business_lines: Optional[List[str]] = None,
    ) -> WindowProfileSnapshot:
        if not actor or not actor.strip():
            raise WindowProfileValidationError("必须指定操作人 actor")

        profile = self.get_profile(profile_name)
        if profile is None:
            raise WindowProfileNotFoundError(
                f"模板不存在或已删除: '{profile_name}'。"
                f"请先创建模板或使用其他模板。"
            )

        self.validate_profile(profile, valid_business_lines)

        if expected_fingerprint and not force:
            self.check_profile_modified(profile, expected_fingerprint)

        self.check_already_applied(profile_name, batch_id)

        snapshot = WindowProfileSnapshot(
            profile_name=profile.name,
            profile_version=profile.version,
            window_start=profile.window_start,
            window_end=profile.window_end,
            timezone=profile.timezone,
            business_lines=list(profile.business_lines),
            notes=profile.notes,
            applied_at=datetime.now().isoformat(),
            applied_by=actor,
            batch_id=batch_id,
            profile_fingerprint=profile.fingerprint(),
        )

        self._save_snapshot(snapshot)

        app_record = WindowProfileApplicationRecord(
            profile_name=profile.name,
            profile_version=profile.version,
            batch_id=batch_id,
            applied_at=snapshot.applied_at,
            applied_by=actor,
            profile_fingerprint=snapshot.profile_fingerprint,
            backup_dir=backup_dir,
        )
        self.applications.append(app_record)

        self._log_operation(
            action=WindowProfileAction.APPLY,
            actor=actor,
            profile_name=profile_name,
            batch_id=batch_id,
            detail={
                "snapshot": snapshot.to_dict(),
            },
        )
        self._save()
        return snapshot

    def _save_snapshot(self, snapshot: WindowProfileSnapshot) -> None:
        path = get_snapshot_path(snapshot.batch_id)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(snapshot.to_dict(), f, ensure_ascii=False, indent=2)

    def load_snapshot(self, batch_id: str) -> Optional[WindowProfileSnapshot]:
        path = get_snapshot_path(batch_id)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return WindowProfileSnapshot.from_dict(data)
        except (json.JSONDecodeError, KeyError):
            return None

    def get_applications_for_batch(self, batch_id: str) -> List[WindowProfileApplicationRecord]:
        return [a for a in self.applications if a.batch_id == batch_id]

    def get_applications_for_profile(self, profile_name: str) -> List[WindowProfileApplicationRecord]:
        return [a for a in self.applications if a.profile_name == profile_name]

    def get_audit_log(self, limit: Optional[int] = None) -> List[WindowProfileAuditLogEntry]:
        log = list(self.audit_log)
        if limit is not None:
            log = log[-limit:]
        return log

    def export_profiles(
        self,
        output_path: str,
        actor: str,
        profile_names: Optional[List[str]] = None,
    ) -> WindowProfileExportBundle:
        if profile_names:
            profiles = []
            for name in profile_names:
                p = self.get_profile(name)
                if p is None:
                    raise WindowProfileNotFoundError(f"模板不存在: '{name}'")
                profiles.append(p)
        else:
            profiles = self.list_profiles()

        bundle = WindowProfileExportBundle(
            profiles=profiles,
        )

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(bundle.to_dict(), f, ensure_ascii=False, indent=2)

        if profile_names:
            for pn in profile_names:
                self._log_operation(
                    action=WindowProfileAction.EXPORT,
                    actor=actor,
                    profile_name=pn,
                    detail={
                        "output_path": output_path,
                        "exported_count": len(profiles),
                        "exported_names": [p.name for p in profiles],
                    },
                )
        else:
            for p in profiles:
                self._log_operation(
                    action=WindowProfileAction.EXPORT,
                    actor=actor,
                    profile_name=p.name,
                    detail={
                        "output_path": output_path,
                        "exported_count": len(profiles),
                        "exported_names": [p.name for p in profiles],
                    },
                )
        self._save()
        return bundle

    def import_profiles(
        self,
        input_path: str,
        actor: str,
        mode: str = "merge",
        force: bool = False,
    ) -> Dict[str, Any]:
        if not actor or not actor.strip():
            raise WindowProfileValidationError("必须指定操作人 actor")

        if mode not in ("merge", "replace"):
            raise WindowProfileValidationError(f"无效的导入模式: '{mode}'。必须为 'merge' 或 'replace'。")

        if not os.path.exists(input_path):
            raise WindowProfileValidationError(f"导入文件不存在: {input_path}")

        try:
            with open(input_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            bundle = WindowProfileExportBundle.from_dict(data)
        except (json.JSONDecodeError, KeyError) as e:
            raise WindowProfileValidationError(f"导入文件格式无效: {e}")

        result: Dict[str, Any] = {
            "total": len(bundle.profiles),
            "added": [],
            "updated": [],
            "skipped": [],
            "conflicts": [],
        }

        for profile in bundle.profiles:
            try:
                self.validate_profile(profile)
            except WindowProfileValidationError as e:
                result["conflicts"].append({
                    "name": profile.name,
                    "error": str(e),
                })
                raise WindowProfileValidationError(
                    f"导入的模板校验失败，已阻止整个导入。{str(e)}"
                )

        existing_names = {p.name for p in self.list_profiles()}

        for profile in bundle.profiles:
            if profile.name in existing_names:
                if mode == "replace":
                    if force:
                        existing = self.get_profile(profile.name)
                        updated = self.update_profile(
                            name=profile.name,
                            actor=actor,
                            window_start=profile.window_start,
                            window_end=profile.window_end,
                            timezone=profile.timezone,
                            business_lines=profile.business_lines,
                            notes=profile.notes,
                        )
                        result["updated"].append(profile.name)
                    else:
                        result["skipped"].append({
                            "name": profile.name,
                            "reason": "已存在，使用 --force 可强制更新（replace 模式）",
                        })
                else:
                    result["skipped"].append({
                        "name": profile.name,
                        "reason": "已存在，merge 模式不覆盖",
                    })
            else:
                self.create_profile(profile, actor)
                result["added"].append(profile.name)

        self._log_operation(
            action=WindowProfileAction.IMPORT,
            actor=actor,
            detail={
                "input_path": input_path,
                "mode": mode,
                "result": result,
            },
        )
        self._save()
        return result
