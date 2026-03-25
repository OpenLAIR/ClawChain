from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RiskDefinition:
    risk_reason: str
    label: str
    category: str
    severity: str
    description: str
    restorable: bool


RISK_DEFINITIONS: tuple[RiskDefinition, ...] = (
    RiskDefinition(
        risk_reason="destructive_delete",
        label="Delete / Remove",
        category="destructive filesystem mutation",
        severity="critical",
        description="Deletes files or directories, including recursive removal.",
        restorable=True,
    ),
    RiskDefinition(
        risk_reason="destructive_git_clean",
        label="Git Clean",
        category="destructive repository mutation",
        severity="critical",
        description="Removes untracked files or directories from a repository.",
        restorable=False,
    ),
    RiskDefinition(
        risk_reason="destructive_git_reset",
        label="Git Hard Reset",
        category="destructive repository mutation",
        severity="critical",
        description="Resets repository state and discards local changes.",
        restorable=False,
    ),
    RiskDefinition(
        risk_reason="destructive_move",
        label="Move / Rename",
        category="destructive filesystem mutation",
        severity="high",
        description="Moves or renames files in a way that may hide or replace data.",
        restorable=False,
    ),
    RiskDefinition(
        risk_reason="sensitive_file_move",
        label="Sensitive File Move",
        category="sensitive asset mutation",
        severity="high",
        description="Moves sensitive files such as configuration or secret-bearing files.",
        restorable=False,
    ),
    RiskDefinition(
        risk_reason="config_integrity_mutation",
        label="Config Overwrite",
        category="configuration integrity",
        severity="high",
        description="Overwrites configuration or settings that can alter runtime behavior.",
        restorable=False,
    ),
    RiskDefinition(
        risk_reason="destructive_permission_change",
        label="Destructive Permission Change",
        category="filesystem permissions",
        severity="high",
        description="Removes access permissions, for example chmod 000.",
        restorable=False,
    ),
    RiskDefinition(
        risk_reason="sensitive_permission_change",
        label="Sensitive Permission Change",
        category="filesystem permissions",
        severity="high",
        description="Changes permissions on sensitive files or locations.",
        restorable=False,
    ),
    RiskDefinition(
        risk_reason="sensitive_ownership_change",
        label="Sensitive Ownership Change",
        category="filesystem ownership",
        severity="high",
        description="Changes ownership of sensitive files or locations.",
        restorable=False,
    ),
    RiskDefinition(
        risk_reason="ownership_change",
        label="Ownership Change",
        category="filesystem ownership",
        severity="medium",
        description="Changes ownership and may affect future access or control.",
        restorable=False,
    ),
    RiskDefinition(
        risk_reason="secret_access",
        label="Secret Access",
        category="secret handling",
        severity="critical",
        description="Reads environment or secret material that should be tracked carefully.",
        restorable=False,
    ),
    RiskDefinition(
        risk_reason="wildcard_destructive_scope",
        label="Wildcard Destructive Scope",
        category="broad destructive command",
        severity="high",
        description="Uses wildcard scope in a destructive command, increasing blast radius uncertainty.",
        restorable=False,
    ),
    RiskDefinition(
        risk_reason="destructive_find_delete",
        label="Find And Delete",
        category="broad destructive command",
        severity="high",
        description="Uses find with delete semantics across a potentially large path set.",
        restorable=False,
    ),
    RiskDefinition(
        risk_reason="destructive_truncate",
        label="Truncate File",
        category="destructive filesystem mutation",
        severity="high",
        description="Truncates a file and destroys its prior contents.",
        restorable=False,
    ),
    RiskDefinition(
        risk_reason="destructive_overwrite",
        label="Raw Overwrite",
        category="destructive filesystem mutation",
        severity="critical",
        description="Overwrites data using low-level destructive write tools such as dd.",
        restorable=False,
    ),
    RiskDefinition(
        risk_reason="dependency_force_reinstall",
        label="Force Reinstall Dependency",
        category="environment mutation",
        severity="medium",
        description="Forces dependency replacement and may destabilize the environment.",
        restorable=False,
    ),
    RiskDefinition(
        risk_reason="in_place_file_edit",
        label="In-Place File Edit",
        category="filesystem mutation",
        severity="medium",
        description="Edits a file in place with tools like sed -i, making rollback important.",
        restorable=False,
    ),
    RiskDefinition(
        risk_reason="sensitive_path_access",
        label="Sensitive Path Access",
        category="sensitive asset access",
        severity="medium",
        description="Touches a sensitive path that may contain secrets or critical runtime state.",
        restorable=False,
    ),
)

RISK_BY_REASON = {item.risk_reason: item for item in RISK_DEFINITIONS}


def risk_definition(reason: str) -> RiskDefinition | None:
    return RISK_BY_REASON.get(str(reason or ''))


def risk_label(reason: str) -> str:
    item = risk_definition(reason)
    return item.label if item else str(reason or '-')


def risk_restorable(reason: str) -> bool:
    item = risk_definition(reason)
    return bool(item.restorable) if item else False


def risk_class(reason: str) -> str:
    return 'restorable' if risk_restorable(reason) else 'audit-only'


def render_risk_filter_options() -> str:
    visible_reasons = (
        "destructive_delete",
        "destructive_git_reset",
        "config_integrity_mutation",
        "secret_access",
        "sensitive_path_access",
    )
    parts = ['<option value="">all risks</option>']
    for reason in visible_reasons:
        item = risk_definition(reason)
        if item is None:
            continue
        parts.append(f'<option value="{item.risk_reason}">{item.label}</option>')
    return "\n".join(parts)


__all__ = [
    'RiskDefinition',
    'RISK_DEFINITIONS',
    'RISK_BY_REASON',
    'risk_definition',
    'risk_label',
    'risk_restorable',
    'risk_class',
    'render_risk_filter_options',
]
