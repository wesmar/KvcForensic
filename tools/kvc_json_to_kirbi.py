#!/usr/bin/env python3
"""Convert Kerberos tickets from a KvcForensic JSON report to KRB-CRED files."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from impacket.krb5.asn1 import (
    EncKrbCredPart,
    KRB_CRED,
    KrbCredInfo,
    PrincipalName,
    Ticket,
    seq_set_iter,
)
from impacket.krb5.types import KerberosTime
from pyasn1.codec.der import encoder


def iter_tickets(report: dict[str, Any]) -> Iterable[dict[str, Any]]:
    for session in report.get("sessions", []):
        for credential in session.get("kerberos", []):
            for ticket in credential.get("tickets", []):
                yield {
                    **ticket,
                    "_user": credential.get("username", credential.get("user", "")),
                    "_credential_domain": credential.get(
                        "domainname", credential.get("domain", "")
                    ),
                }


def fill_principal(value: PrincipalName, name_type: int, components: list[str]) -> None:
    value["name-type"] = int(name_type or 1)
    seq_set_iter(value, "name-string", [part.encode("utf-8") for part in components])


def kerberos_time(value: str) -> Any:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return KerberosTime.to_asn1(parsed)


def split_name(value: str) -> list[str]:
    return [part for part in value.split("/") if part]


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._@$-]+", "_", value).strip("_")[:80] or "ticket"


def build_kirbi(ticket: dict[str, Any]) -> bytes:
    cipher = bytes.fromhex(ticket["ticket"])
    session_key = ticket.get("session_key")
    if not session_key:
        raise ValueError(
            "ticket has no session_key; reprocess the dump with the fixed KvcForensic"
        )
    if not ticket.get("start_time") or not ticket.get("end_time"):
        raise ValueError("ticket has no start_time/end_time; reprocess the dump")

    realm = ticket.get("domain") or ticket["_credential_domain"]
    service_components = ticket.get("service_components") or split_name(
        ticket.get("service", "")
    )
    client_components = ticket.get("client_components") or split_name(
        ticket.get("client", "")
    ) or [ticket["_user"]]
    prealm = ticket.get("alt_target_domain") or ticket["_credential_domain"]

    krb_ticket = Ticket()
    krb_ticket["tkt-vno"] = 5
    krb_ticket["realm"] = realm.encode("utf-8")
    fill_principal(
        krb_ticket["sname"], ticket.get("service_name_type", 2), service_components
    )
    krb_ticket["enc-part"]["etype"] = int(ticket["enc_type"])
    krb_ticket["enc-part"]["kvno"] = int(ticket["kvno"])
    krb_ticket["enc-part"]["cipher"] = cipher

    cred_info = KrbCredInfo()
    cred_info["key"]["keytype"] = int(ticket.get("key_type") or ticket["enc_type"])
    cred_info["key"]["keyvalue"] = bytes.fromhex(session_key)
    cred_info["prealm"] = prealm.encode("utf-8")
    fill_principal(
        cred_info["pname"], ticket.get("client_name_type", 1), client_components
    )
    cred_info["flags"] = f"{int(ticket['flags'], 16):032b}"
    cred_info["starttime"] = kerberos_time(ticket["start_time"])
    cred_info["endtime"] = kerberos_time(ticket["end_time"])
    if ticket.get("renew_until"):
        cred_info["renew-till"] = kerberos_time(ticket["renew_until"])
    cred_info["srealm"] = realm.encode("utf-8")
    fill_principal(
        cred_info["sname"], ticket.get("service_name_type", 2), service_components
    )

    enc_part = EncKrbCredPart()
    seq_set_iter(enc_part, "ticket-info", [cred_info])

    krb_cred = KRB_CRED()
    krb_cred["pvno"] = 5
    krb_cred["msg-type"] = 22
    seq_set_iter(krb_cred, "tickets", [krb_ticket])
    krb_cred["enc-part"]["etype"] = 0
    krb_cred["enc-part"]["cipher"] = encoder.encode(enc_part)

    return encoder.encode(krb_cred)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path, help="KvcForensic JSON report")
    parser.add_argument("output_dir", type=Path, help="directory for .kirbi files")
    parser.add_argument("--index", type=int, help="zero-based ticket index")
    parser.add_argument("--service", help="only tickets with this service name")
    args = parser.parse_args()

    report = json.loads(args.report.read_text(encoding="utf-8"))
    tickets = list(iter_tickets(report))
    selected = [
        (index, ticket)
        for index, ticket in enumerate(tickets)
        if (args.index is None or index == args.index)
        and (args.service is None or args.service == ticket.get("service"))
    ]
    if not selected:
        parser.error("no matching tickets")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    for index, ticket in selected:
        file_name = "_".join(
            [
                safe_name(ticket["_credential_domain"]),
                safe_name(ticket["_user"]),
                safe_name(ticket.get("service", "ticket")),
                f"etype{int(ticket['enc_type'])}",
                str(index),
            ]
        )
        path = args.output_dir / f"{file_name}.kirbi"
        path.write_bytes(build_kirbi(ticket))
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
