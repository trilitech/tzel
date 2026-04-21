#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def build_params(
    constants_path: Path,
    accounts_path: Path,
    out_path: Path,
    operator_pk: str,
    attestation_lag: int,
    bootstrap_pks: list[str],
) -> None:
    data = json.loads(constants_path.read_text(encoding="utf-8"))
    accounts = json.loads(accounts_path.read_text(encoding="utf-8"))

    bootstrap_accounts = []
    for account, pk in zip(accounts, bootstrap_pks, strict=True):
        bootstrap_accounts.append([pk, account["amount"]])
    bootstrap_accounts.append([operator_pk, "3800000000000"])

    data["bootstrap_accounts"] = bootstrap_accounts
    data.pop("chain_id", None)
    data.pop("initial_timestamp", None)
    data["minimal_block_delay"] = "1"
    data["delay_increment_per_round"] = "1"
    dal = data.setdefault("dal_parametric", {})
    dal["attestation_lag"] = attestation_lag
    if "attestation_lags" in dal:
        # Some newer Octez builds require the final attestation_lags entry to
        # match attestation_lag. Preserve compatibility by only rewriting the
        # list when the source constants already expose that field, and only
        # update the trailing value instead of collapsing the whole vector.
        lags = list(dal["attestation_lags"])
        if lags:
            lags[-1] = attestation_lag
        else:
            lags = [attestation_lag]
        dal["attestation_lags"] = lags

    out_path.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-constants", required=True)
    parser.add_argument("--bootstrap-accounts", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--operator-pk", required=True)
    parser.add_argument("--attestation-lag", required=True, type=int)
    parser.add_argument(
        "--bootstrap-pk",
        dest="bootstrap_pks",
        action="append",
        required=True,
    )
    args = parser.parse_args()

    build_params(
        constants_path=Path(args.raw_constants),
        accounts_path=Path(args.bootstrap_accounts),
        out_path=Path(args.out),
        operator_pk=args.operator_pk,
        attestation_lag=args.attestation_lag,
        bootstrap_pks=args.bootstrap_pks,
    )


if __name__ == "__main__":
    main()
