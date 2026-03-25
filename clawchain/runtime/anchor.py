from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
import json
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from typing import Protocol

from ..canonical.ids import digest_text, stable_json
from .batching import AnchorReceipt


class AnchorBackend(Protocol):
    def submit(self, receipt: AnchorReceipt) -> AnchorReceipt: ...


class AnchorSubmissionExporter(Protocol):
    def drain_submissions(self) -> list["AnchorSubmission"]: ...


class AnchorSubmissionPoller(Protocol):
    def poll_submissions(self, submissions: list["AnchorSubmission"]) -> list["AnchorSubmission"]: ...


@dataclass(frozen=True, kw_only=True)
class AnchorSubmission:
    session_id: str
    batch_seq_no: int
    merkle_root: str
    event_ids: tuple[str, ...]
    anchor_mode: str
    anchor_backend: str
    anchor_reference: str
    metadata: dict[str, object]
    commitment_type: str = "event_batch"
    subject_id: str | None = None
    status: str = "submitted"


@dataclass(frozen=True)
class EvmRpcRequest:
    method: str
    params: list[object]
    request_id: int = 1
    jsonrpc: str = "2.0"


@dataclass(frozen=True)
class EvmRpcResponse:
    result: object | None = None
    error: dict[str, object] | None = None
    request_id: int = 1
    jsonrpc: str = "2.0"


@dataclass(frozen=True)
class EvmBroadcastResult:
    tx_hash: str
    status: str
    confirmations: int
    network: int | None
    block_number: int | None = None
    raw_response: dict[str, object] | None = None


@dataclass(frozen=True)
class EvmPollResult:
    tx_hash: str
    status: str
    confirmations: int
    block_number: int | None = None
    raw_response: dict[str, object] | None = None


@dataclass(frozen=True)
class EvmChainProbe:
    rpc_url: str
    client_version: str | None
    chain_id: int | None
    latest_block: int | None
    contract_address: str | None = None
    contract_code: str | None = None
    contract_code_present: bool = False
    configured_chain_id: int | None = None
    chain_id_matches: bool | None = None


@dataclass(frozen=True)
class EvmDeploymentManifest:
    chain_id: int
    rpc_url: str
    contract_address: str
    contract_name: str = "CommitmentAnchor"
    source_path: str | None = None
    abi_path: str | None = None
    deployed_at_block: int | None = None
    deploy_tx_hash: str | None = None
    notes: str | None = None


@dataclass(frozen=True)
class EvmDeploymentVerificationReport:
    ok: bool
    manifest: EvmDeploymentManifest
    probe: EvmChainProbe | None
    findings: tuple[str, ...]
    error: str | None = None


@dataclass(frozen=True)
class EvmCommitmentLookup:
    found: bool
    session_id: str
    batch_seq_no: int
    merkle_root: str
    anchored_at_block: int
    submitter: str
    raw_response: str


@dataclass
class LocalAnchorBackend:
    submissions: list[AnchorSubmission] = field(default_factory=list)

    def submit(self, receipt: AnchorReceipt) -> AnchorReceipt:
        anchored = replace(
            receipt,
            anchor_mode="local",
            anchor_backend="local-json",
            anchor_reference=f"local:{receipt.session_id}:{receipt.batch_seq_no}",
        )
        self.submissions.append(
            AnchorSubmission(
                session_id=anchored.session_id,
                batch_seq_no=anchored.batch_seq_no,
                merkle_root=anchored.merkle_root,
                event_ids=anchored.event_ids,
                commitment_type=anchored.commitment_type,
                subject_id=anchored.subject_id,
                anchor_mode=anchored.anchor_mode,
                anchor_backend=anchored.anchor_backend or "local-json",
                anchor_reference=anchored.anchor_reference or "",
                metadata={
                    "storage": "json",
                    **(anchored.metadata or {}),
                },
            )
        )
        return anchored

    def drain_submissions(self) -> list[AnchorSubmission]:
        drained = self.submissions[:]
        self.submissions.clear()
        return drained


@dataclass
class SimulatedChainBackend:
    chain_name: str = "simulated-devnet"
    receipts: list[AnchorSubmission] = field(default_factory=list)

    def submit(self, receipt: AnchorReceipt) -> AnchorReceipt:
        submission = AnchorSubmission(
            session_id=receipt.session_id,
            batch_seq_no=receipt.batch_seq_no,
            merkle_root=receipt.merkle_root,
            event_ids=receipt.event_ids,
            commitment_type=receipt.commitment_type,
            subject_id=receipt.subject_id,
            anchor_mode="simulated-chain",
            anchor_backend=self.chain_name,
            anchor_reference=f"sim:{self.chain_name}:{receipt.session_id}:{receipt.batch_seq_no}",
            metadata={
                "chain_name": self.chain_name,
                **(receipt.metadata or {}),
                "receipt_hash": digest_text(
                    stable_json(
                        {
                            "session_id": receipt.session_id,
                            "batch_seq_no": receipt.batch_seq_no,
                            "merkle_root": receipt.merkle_root,
                            "event_ids": receipt.event_ids,
                            "commitment_type": receipt.commitment_type,
                            "subject_id": receipt.subject_id,
                        }
                    )
                ),
            },
        )
        self.receipts.append(submission)
        return replace(
            receipt,
            anchor_mode=submission.anchor_mode,
            anchor_backend=submission.anchor_backend,
            anchor_reference=submission.anchor_reference,
        )

    def drain_submissions(self) -> list[AnchorSubmission]:
        drained = self.receipts[:]
        self.receipts.clear()
        return drained


@dataclass(frozen=True)
class EvmAnchorConfig:
    chain_id: int
    rpc_url: str
    contract_address: str
    contract_name: str = "CommitmentAnchor"
    submitter: str = "clawchain"
    method_name: str = "anchorCommitment"
    polling_enabled: bool = False
    required_confirmations: int = 1
    max_poll_attempts: int = 8
    poll_interval_sec: float = 2.0


def resolve_contracts_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "contracts"


def resolve_commitment_anchor_source_path() -> Path:
    return resolve_contracts_dir() / "CommitmentAnchor.sol"


def resolve_commitment_anchor_abi_path() -> Path:
    return resolve_contracts_dir() / "CommitmentAnchor.abi.json"


def load_commitment_anchor_abi() -> list[dict[str, object]]:
    return json.loads(resolve_commitment_anchor_abi_path().read_text(encoding="utf-8"))


def deployment_manifest_to_dict(manifest: EvmDeploymentManifest) -> dict[str, object]:
    return asdict(manifest)


def load_evm_deployment_manifest(path: Path) -> EvmDeploymentManifest:
    decoded = json.loads(path.read_text(encoding="utf-8"))
    return EvmDeploymentManifest(
        chain_id=int(decoded["chain_id"]),
        rpc_url=str(decoded["rpc_url"]),
        contract_address=str(decoded["contract_address"]),
        contract_name=str(decoded.get("contract_name", "CommitmentAnchor")),
        source_path=str(decoded["source_path"]) if decoded.get("source_path") is not None else None,
        abi_path=str(decoded["abi_path"]) if decoded.get("abi_path") is not None else None,
        deployed_at_block=(
            int(decoded["deployed_at_block"]) if decoded.get("deployed_at_block") is not None else None
        ),
        deploy_tx_hash=(
            str(decoded["deploy_tx_hash"]) if decoded.get("deploy_tx_hash") is not None else None
        ),
        notes=str(decoded["notes"]) if decoded.get("notes") is not None else None,
    )


def write_evm_deployment_manifest(path: Path, manifest: EvmDeploymentManifest) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(deployment_manifest_to_dict(manifest), ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )


def _is_hex_address(value: str) -> bool:
    normalized = value.lower()
    if not normalized.startswith("0x") or len(normalized) != 42:
        return False
    try:
        int(normalized[2:], 16)
    except ValueError:
        return False
    return True


def _load_abi_from_path(path: Path) -> list[dict[str, object]]:
    decoded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(decoded, list):
        raise ValueError(f"ABI payload must be a list, got {type(decoded).__name__}")
    rows: list[dict[str, object]] = []
    for entry in decoded:
        if not isinstance(entry, dict):
            raise ValueError(f"ABI entry must be an object, got {type(entry).__name__}")
        rows.append(entry)
    return rows


def validate_commitment_anchor_abi(abi: list[dict[str, object]]) -> tuple[str, ...]:
    findings: list[str] = []
    names_by_type = {
        (str(entry.get("type")), str(entry.get("name")))
        for entry in abi
        if entry.get("type") is not None and entry.get("name") is not None
    }
    if ("function", "anchorCommitment") not in names_by_type:
        findings.append("abi_missing_anchor_commitment")
    if ("function", "getCommitment") not in names_by_type:
        findings.append("abi_missing_get_commitment")
    if ("event", "CommitmentAnchored") not in names_by_type:
        findings.append("abi_missing_commitment_anchored_event")
    has_fallback = any(str(entry.get("type")) == "fallback" for entry in abi)
    if not has_fallback:
        findings.append("abi_missing_fallback")
    return tuple(findings)


def validate_evm_deployment_manifest(manifest: EvmDeploymentManifest) -> tuple[str, ...]:
    findings: list[str] = []
    if manifest.chain_id <= 0:
        findings.append("invalid_chain_id")
    if not manifest.rpc_url.strip():
        findings.append("missing_rpc_url")
    if not _is_hex_address(manifest.contract_address):
        findings.append("invalid_contract_address")
    source_path = Path(manifest.source_path) if manifest.source_path is not None else None
    abi_path = Path(manifest.abi_path) if manifest.abi_path is not None else None
    if source_path is None:
        findings.append("missing_source_path")
    elif not source_path.exists():
        findings.append("source_path_missing")
    if abi_path is None:
        findings.append("missing_abi_path")
    elif not abi_path.exists():
        findings.append("abi_path_missing")
    if abi_path is not None and abi_path.exists():
        try:
            abi = _load_abi_from_path(abi_path)
        except Exception:
            findings.append("abi_invalid_json")
        else:
            findings.extend(validate_commitment_anchor_abi(abi))
    return tuple(findings)


def verify_evm_deployment_manifest(
    manifest: EvmDeploymentManifest, *, broadcaster: "RpcEvmBroadcaster | None" = None
) -> EvmDeploymentVerificationReport:
    static_findings = list(validate_evm_deployment_manifest(manifest))
    if static_findings:
        return EvmDeploymentVerificationReport(
            ok=False,
            manifest=manifest,
            probe=None,
            findings=tuple(static_findings),
            error=None,
        )
    broadcaster = broadcaster or RpcEvmBroadcaster(rpc_url=manifest.rpc_url)
    try:
        probe = broadcaster.probe_chain(
            configured_chain_id=manifest.chain_id,
            contract_address=manifest.contract_address,
        )
    except Exception as err:
        return EvmDeploymentVerificationReport(
            ok=False,
            manifest=manifest,
            probe=None,
            findings=("rpc_unreachable",),
            error=str(err),
        )

    findings: list[str] = []
    if probe.chain_id_matches is False:
        findings.append("chain_id_mismatch")
    if not probe.contract_code_present:
        findings.append("contract_code_missing")
    if probe.client_version is None:
        findings.append("client_version_missing")
    if probe.latest_block is None:
        findings.append("latest_block_missing")
    return EvmDeploymentVerificationReport(
        ok=not findings,
        manifest=manifest,
        probe=probe,
        findings=tuple(findings),
        error=None,
    )


def _encode_uint256(value: int) -> str:
    if value < 0:
        raise ValueError(f"uint256 value must be non-negative, got {value}")
    return f"{value:064x}"


def _normalize_bytes32_hex(value: str) -> str:
    normalized = value.lower()
    if normalized.startswith("0x"):
        normalized = normalized[2:]
    if len(normalized) != 64:
        raise ValueError(f"bytes32 value must be 32 bytes, got {value!r}")
    try:
        int(normalized, 16)
    except ValueError as err:
        raise ValueError(f"bytes32 value must be hex-encoded, got {value!r}") from err
    return normalized


def encode_anchor_commitment_calldata(*, session_id: str, batch_seq_no: int, merkle_root: str) -> str:
    """Encode abi.encode(string,uint256,bytes32) for fallback-based EVM anchoring.

    This avoids requiring an external ABI/keccak dependency while still producing
    valid calldata that a Solidity fallback can decode with:
    abi.decode(msg.data, (string, uint256, bytes32))
    """

    session_bytes = session_id.encode("utf-8")
    dynamic_offset = 32 * 3
    padded_string_len = ((len(session_bytes) + 31) // 32) * 32
    padded_string_hex = session_bytes.hex().ljust(padded_string_len * 2, "0")
    encoded = (
        _encode_uint256(dynamic_offset)
        + _encode_uint256(batch_seq_no)
        + _normalize_bytes32_hex(merkle_root)
        + _encode_uint256(len(session_bytes))
        + padded_string_hex
    )
    return f"0x{encoded}"


def encode_commitment_lookup_calldata(*, session_id: str, batch_seq_no: int, merkle_root: str) -> str:
    session_bytes = session_id.encode("utf-8")
    dynamic_offset = 32 * 4
    padded_string_len = ((len(session_bytes) + 31) // 32) * 32
    padded_string_hex = session_bytes.hex().ljust(padded_string_len * 2, "0")
    encoded = (
        _encode_uint256(1)
        + _encode_uint256(dynamic_offset)
        + _encode_uint256(batch_seq_no)
        + _normalize_bytes32_hex(merkle_root)
        + _encode_uint256(len(session_bytes))
        + padded_string_hex
    )
    return f"0x{encoded}"


def _read_word(raw_hex: str, index: int) -> str:
    start = index * 64
    end = start + 64
    return raw_hex[start:end]


def _decode_dynamic_string(raw_hex: str, offset_words_index: int) -> str:
    offset_bytes = int(_read_word(raw_hex, offset_words_index), 16)
    offset_words = offset_bytes // 32
    length = int(_read_word(raw_hex, offset_words), 16)
    data_start = (offset_words + 1) * 64
    data_end = data_start + (length * 2)
    return bytes.fromhex(raw_hex[data_start:data_end]).decode("utf-8")


def decode_commitment_lookup_result(raw_result: str) -> EvmCommitmentLookup:
    normalized = raw_result[2:] if raw_result.startswith("0x") else raw_result
    if len(normalized) < 64 * 6:
        raise ValueError(f"lookup result too short: {raw_result!r}")
    found = int(_read_word(normalized, 0), 16) != 0
    session_id = _decode_dynamic_string(normalized, 1)
    batch_seq_no = int(_read_word(normalized, 2), 16)
    merkle_root = f"0x{_read_word(normalized, 3)}"
    anchored_at_block = int(_read_word(normalized, 4), 16)
    submitter = f"0x{_read_word(normalized, 5)[24:]}"
    return EvmCommitmentLookup(
        found=found,
        session_id=session_id,
        batch_seq_no=batch_seq_no,
        merkle_root=merkle_root,
        anchored_at_block=anchored_at_block,
        submitter=submitter,
        raw_response=raw_result,
    )


class EvmBroadcaster(Protocol):
    def broadcast(self, tx_intent: dict[str, object]) -> EvmBroadcastResult: ...

    def poll(self, tx_reference: str) -> EvmPollResult: ...


@dataclass
class NoopEvmBroadcaster:
    def broadcast(self, tx_intent: dict[str, object]) -> EvmBroadcastResult:
        tx_hash = f"0x{digest_text(stable_json(tx_intent))}"
        return EvmBroadcastResult(
            tx_hash=tx_hash,
            status="pending",
            confirmations=0,
            network=int(tx_intent.get("chain_id")) if tx_intent.get("chain_id") is not None else None,
            raw_response={"mode": "noop"},
        )

    def poll(self, tx_reference: str) -> EvmPollResult:
        return EvmPollResult(
            tx_hash=tx_reference,
            status="pending",
            confirmations=0,
            raw_response={"mode": "noop"},
        )


@dataclass
class DeterministicEvmBroadcaster:
    confirmations_after: int = 2
    poll_counts: dict[str, int] = field(default_factory=dict)

    def broadcast(self, tx_intent: dict[str, object]) -> EvmBroadcastResult:
        tx_hash = f"0x{digest_text(stable_json(tx_intent))}"
        self.poll_counts.setdefault(tx_hash, 0)
        return EvmBroadcastResult(
            tx_hash=tx_hash,
            status="pending",
            confirmations=0,
            network=int(tx_intent.get("chain_id")) if tx_intent.get("chain_id") is not None else None,
            raw_response={"mode": "deterministic"},
        )

    def poll(self, tx_reference: str) -> EvmPollResult:
        count = self.poll_counts.get(tx_reference, 0) + 1
        self.poll_counts[tx_reference] = count
        confirmations = 1 if count >= self.confirmations_after else 0
        return EvmPollResult(
            tx_hash=tx_reference,
            status="confirmed" if confirmations > 0 else "pending",
            confirmations=confirmations,
            block_number=1_000 + count if confirmations > 0 else None,
            raw_response={"mode": "deterministic", "poll_count": count},
        )


@dataclass
class RpcEvmBroadcaster:
    rpc_url: str

    @staticmethod
    def _is_hex_address(value: object) -> bool:
        if not isinstance(value, str):
            return False
        if not value.startswith("0x") or len(value) != 42:
            return False
        try:
            int(value[2:], 16)
        except ValueError:
            return False
        return True

    def _resolve_submitter(self, submitter: object) -> str:
        if self._is_hex_address(submitter):
            return str(submitter)
        accounts_response = self.send(EvmRpcRequest(method="eth_accounts", params=[]))
        if accounts_response.error is not None:
            raise RuntimeError(
                "RpcEvmBroadcaster.resolve_submitter RPC error: "
                f"{accounts_response.error.get('code')} {accounts_response.error.get('message')}"
            )
        accounts = accounts_response.result
        if not isinstance(accounts, list):
            raise RuntimeError(
                f"RpcEvmBroadcaster.resolve_submitter invalid accounts payload: {accounts!r}"
            )
        for candidate in accounts:
            if self._is_hex_address(candidate):
                return str(candidate)
        raise RuntimeError("RpcEvmBroadcaster.resolve_submitter found no unlocked accounts")

    def build_broadcast_request(self, tx_intent: dict[str, object]) -> EvmRpcRequest:
        call_payload = tx_intent["call_payload"]
        encoded_data = call_payload.get("encoded_data")
        if not isinstance(encoded_data, str) or not encoded_data:
            encoded_data = f"0x{digest_text(stable_json(call_payload))}"
        submitter = self._resolve_submitter(tx_intent.get("submitter"))
        return EvmRpcRequest(
            method="eth_sendTransaction",
            params=[
                {
                    "to": call_payload["contract_address"],
                    "data": encoded_data,
                    "from": submitter,
                }
            ],
        )

    def build_poll_requests(self, tx_reference: str) -> tuple[EvmRpcRequest, EvmRpcRequest]:
        return (
            EvmRpcRequest(method="eth_getTransactionReceipt", params=[tx_reference]),
            EvmRpcRequest(method="eth_blockNumber", params=[]),
        )

    def build_probe_requests(
        self, contract_address: str | None = None
    ) -> tuple[EvmRpcRequest, EvmRpcRequest, EvmRpcRequest, EvmRpcRequest | None]:
        code_request = None
        if contract_address is not None:
            code_request = EvmRpcRequest(method="eth_getCode", params=[contract_address, "latest"])
        return (
            EvmRpcRequest(method="web3_clientVersion", params=[]),
            EvmRpcRequest(method="eth_chainId", params=[]),
            EvmRpcRequest(method="eth_blockNumber", params=[]),
            code_request,
        )

    def build_call_request(self, *, to: str, data: str) -> EvmRpcRequest:
        return EvmRpcRequest(
            method="eth_call",
            params=[
                {
                    "to": to,
                    "data": data,
                },
                "latest",
            ],
        )

    def send(self, request: EvmRpcRequest) -> EvmRpcResponse:
        payload = json.dumps(
            {
                "jsonrpc": request.jsonrpc,
                "id": request.request_id,
                "method": request.method,
                "params": request.params,
            },
            ensure_ascii=True,
        ).encode("utf-8")
        http_request = Request(
            self.rpc_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(http_request) as response:
                raw_body = response.read().decode("utf-8")
        except HTTPError as err:
            body = err.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"RpcEvmBroadcaster.send HTTP {err.code} for {request.method}: {body}"
            ) from err
        except URLError as err:
            raise RuntimeError(
                f"RpcEvmBroadcaster.send transport failure for {request.method}: {err.reason}"
            ) from err

        try:
            decoded = json.loads(raw_body)
        except json.JSONDecodeError as err:
            raise RuntimeError(
                f"RpcEvmBroadcaster.send returned non-JSON response for {request.method}: {raw_body}"
            ) from err

        if not isinstance(decoded, dict):
            raise RuntimeError(
                f"RpcEvmBroadcaster.send returned invalid response shape for {request.method}: {decoded!r}"
            )
        return EvmRpcResponse(
            result=decoded.get("result"),
            error=decoded.get("error") if isinstance(decoded.get("error"), dict) else None,
            request_id=int(decoded.get("id", request.request_id)),
            jsonrpc=str(decoded.get("jsonrpc", request.jsonrpc)),
        )

    def broadcast(self, tx_intent: dict[str, object]) -> EvmBroadcastResult:
        request = self.build_broadcast_request(tx_intent)
        response = self.send(request)
        if response.error is not None:
            raise RuntimeError(
                "RpcEvmBroadcaster.broadcast RPC error: "
                f"{response.error.get('code')} {response.error.get('message')}"
            )
        if not isinstance(response.result, str) or not response.result:
            raise RuntimeError(
                f"RpcEvmBroadcaster.broadcast missing tx hash in response: {asdict(response)}"
            )
        return EvmBroadcastResult(
            tx_hash=response.result,
            status="pending",
            confirmations=0,
            network=int(tx_intent.get("chain_id")) if tx_intent.get("chain_id") is not None else None,
            raw_response=asdict(response),
        )

    def poll(self, tx_reference: str) -> EvmPollResult:
        receipt_request, block_request = self.build_poll_requests(tx_reference)
        receipt_response = self.send(receipt_request)
        if receipt_response.error is not None:
            raise RuntimeError(
                "RpcEvmBroadcaster.poll receipt RPC error: "
                f"{receipt_response.error.get('code')} {receipt_response.error.get('message')}"
            )
        block_response = self.send(block_request)
        if block_response.error is not None:
            raise RuntimeError(
                "RpcEvmBroadcaster.poll block RPC error: "
                f"{block_response.error.get('code')} {block_response.error.get('message')}"
            )

        receipt = receipt_response.result
        if receipt is None:
            return EvmPollResult(
                tx_hash=tx_reference,
                status="pending",
                confirmations=0,
                raw_response={
                    "receipt": asdict(receipt_response),
                    "block": asdict(block_response),
                },
            )
        if not isinstance(receipt, dict):
            raise RuntimeError(
                f"RpcEvmBroadcaster.poll invalid receipt payload: {receipt!r}"
            )

        block_number_hex = receipt.get("blockNumber")
        tx_status_hex = receipt.get("status")
        latest_block_hex = block_response.result
        block_number = int(block_number_hex, 16) if isinstance(block_number_hex, str) else None
        latest_block = int(latest_block_hex, 16) if isinstance(latest_block_hex, str) else None
        confirmations = 0
        if block_number is not None and latest_block is not None and latest_block >= block_number:
            confirmations = latest_block - block_number + 1
        status = "confirmed"
        if isinstance(tx_status_hex, str) and tx_status_hex.lower() == "0x0":
            status = "reverted"
        elif confirmations == 0:
            status = "pending"
        return EvmPollResult(
            tx_hash=tx_reference,
            status=status,
            confirmations=confirmations,
            block_number=block_number,
            raw_response={
                "receipt": asdict(receipt_response),
                "block": asdict(block_response),
            },
        )

    def probe_chain(
        self, *, configured_chain_id: int | None = None, contract_address: str | None = None
    ) -> EvmChainProbe:
        client_request, chain_request, block_request, code_request = self.build_probe_requests(
            contract_address
        )
        client_response = self.send(client_request)
        chain_response = self.send(chain_request)
        block_response = self.send(block_request)
        code_response = self.send(code_request) if code_request is not None else None
        if client_response.error is not None:
            raise RuntimeError(
                "RpcEvmBroadcaster.probe_chain client RPC error: "
                f"{client_response.error.get('code')} {client_response.error.get('message')}"
            )
        if chain_response.error is not None:
            raise RuntimeError(
                "RpcEvmBroadcaster.probe_chain chain RPC error: "
                f"{chain_response.error.get('code')} {chain_response.error.get('message')}"
            )
        if block_response.error is not None:
            raise RuntimeError(
                "RpcEvmBroadcaster.probe_chain block RPC error: "
                f"{block_response.error.get('code')} {block_response.error.get('message')}"
            )
        if code_response is not None and code_response.error is not None:
            raise RuntimeError(
                "RpcEvmBroadcaster.probe_chain code RPC error: "
                f"{code_response.error.get('code')} {code_response.error.get('message')}"
            )
        chain_id = int(chain_response.result, 16) if isinstance(chain_response.result, str) else None
        latest_block = (
            int(block_response.result, 16) if isinstance(block_response.result, str) else None
        )
        contract_code = code_response.result if code_response is not None else None
        code_present = isinstance(contract_code, str) and contract_code not in {"0x", "0x0", ""}
        return EvmChainProbe(
            rpc_url=self.rpc_url,
            client_version=(
                str(client_response.result) if client_response.result is not None else None
            ),
            chain_id=chain_id,
            latest_block=latest_block,
            contract_address=contract_address,
            contract_code=str(contract_code) if contract_code is not None else None,
            contract_code_present=code_present,
            configured_chain_id=configured_chain_id,
            chain_id_matches=(
                chain_id == configured_chain_id
                if chain_id is not None and configured_chain_id is not None
                else None
            ),
        )

    def lookup_commitment(
        self, *, contract_address: str, session_id: str, batch_seq_no: int, merkle_root: str
    ) -> EvmCommitmentLookup:
        request = self.build_call_request(
            to=contract_address,
            data=encode_commitment_lookup_calldata(
                session_id=session_id,
                batch_seq_no=batch_seq_no,
                merkle_root=merkle_root,
            ),
        )
        response = self.send(request)
        if response.error is not None:
            raise RuntimeError(
                "RpcEvmBroadcaster.lookup_commitment RPC error: "
                f"{response.error.get('code')} {response.error.get('message')}"
            )
        if not isinstance(response.result, str):
            raise RuntimeError(
                f"RpcEvmBroadcaster.lookup_commitment returned invalid result: {response.result!r}"
            )
        return decode_commitment_lookup_result(response.result)


@dataclass
class EvmAnchorBackend:
    config: EvmAnchorConfig
    broadcaster: EvmBroadcaster = field(default_factory=NoopEvmBroadcaster)
    submissions: list[AnchorSubmission] = field(default_factory=list)

    def build_call_payload(self, receipt: AnchorReceipt) -> dict[str, object]:
        encoded_data = encode_anchor_commitment_calldata(
            session_id=receipt.session_id,
            batch_seq_no=receipt.batch_seq_no,
            merkle_root=receipt.merkle_root,
        )
        return {
            "contract_name": self.config.contract_name,
            "contract_address": self.config.contract_address,
            "method_name": self.config.method_name,
            "encoding_mode": "abi-fallback-v1",
            "encoded_data": encoded_data,
            "args": {
                "session_id": receipt.session_id,
                "batch_seq_no": receipt.batch_seq_no,
                "merkle_root": receipt.merkle_root,
            },
        }

    def submit(self, receipt: AnchorReceipt) -> AnchorReceipt:
        call_payload = self.build_call_payload(receipt)
        tx_intent = {
            "chain_id": self.config.chain_id,
            "rpc_url": self.config.rpc_url,
            "submitter": self.config.submitter,
            "call_payload": call_payload,
        }
        broadcast = self.broadcaster.broadcast(tx_intent)
        tx_hash = broadcast.tx_hash
        submission = AnchorSubmission(
            session_id=receipt.session_id,
            batch_seq_no=receipt.batch_seq_no,
            merkle_root=receipt.merkle_root,
            event_ids=receipt.event_ids,
            commitment_type=receipt.commitment_type,
            subject_id=receipt.subject_id,
            anchor_mode="evm-pending",
            anchor_backend=f"evm:{self.config.chain_id}",
            anchor_reference=tx_hash,
            metadata={
                "tx_intent": tx_intent,
                **(receipt.metadata or {}),
                "call_data_hash": digest_text(call_payload["encoded_data"]),
                "broadcast": asdict(broadcast),
                "poll_attempts": 0,
            },
            status=broadcast.status,
        )
        self.submissions.append(submission)
        return replace(
            receipt,
            anchor_mode=submission.anchor_mode,
            anchor_backend=submission.anchor_backend,
            anchor_reference=submission.anchor_reference,
        )

    def export_submissions(self) -> list[dict[str, object]]:
        return [asdict(submission) for submission in self.submissions]

    def drain_submissions(self) -> list[AnchorSubmission]:
        drained = self.submissions[:]
        self.submissions.clear()
        return drained

    def poll_submissions(self, submissions: list[AnchorSubmission]) -> list[AnchorSubmission]:
        polled: list[AnchorSubmission] = []
        for submission in submissions:
            if not self.config.polling_enabled:
                polled.append(submission)
                continue
            status = self.broadcaster.poll(submission.anchor_reference)
            confirmations = status.confirmations
            attempts = int(submission.metadata.get("poll_attempts", 0)) + 1
            final_status = (
                "confirmed"
                if confirmations >= self.config.required_confirmations
                else (
                    "reverted"
                    if status.status == "reverted"
                    else (
                    "timeout"
                    if attempts >= self.config.max_poll_attempts and status.status == "pending"
                    else status.status
                    )
                )
            )
            final_anchor_mode = (
                "evm-confirmed"
                if final_status == "confirmed"
                else (
                    "evm-reverted"
                    if final_status == "reverted"
                    else "evm-timeout" if final_status == "timeout" else submission.anchor_mode
                )
            )
            merged_metadata = {
                **submission.metadata,
                "poll": asdict(status),
                "poll_attempts": attempts,
            }
            polled.append(
                replace(
                    submission,
                    anchor_mode=final_anchor_mode,
                    status=final_status,
                    metadata=merged_metadata,
                )
            )
        return polled
