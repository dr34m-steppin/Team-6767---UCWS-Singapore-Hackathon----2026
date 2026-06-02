#!/usr/bin/env python3
"""
kosong_phucs: autonomous SEA e-commerce fraud detection and resolution agent.

The demo intentionally uses only the Python standard library so it can run
cleanly during a hackathon without dependency installation.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parent
CASE_FILE = ROOT / "data" / "cases.json"


@dataclass
class Signal:
    name: str
    weight: int
    evidence: str
    pattern: str


@dataclass
class Investigation:
    case_id: str
    risk_score: int
    confidence: float
    decision: str
    resolution: list[str]
    signals: list[Signal]
    edge_reasons: list[str]
    evidence_brief: str
    case: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        output = asdict(self)
        output["signals"] = [asdict(signal) for signal in self.signals]
        return output


class KosongPhucsAgent:
    def __init__(self, cases: list[dict[str, Any]]):
        self.cases = {case["id"]: case for case in cases}

    def investigate(self, case_id: str) -> Investigation:
        case = self.cases[case_id]
        signals = self._collect_signals(case)
        risk_score = max(0, min(100, sum(signal.weight for signal in signals)))
        edge_reasons = self._edge_reasons(case, signals, risk_score)
        confidence = self._confidence(case, signals, edge_reasons)
        decision = self._decide(case, risk_score, confidence, edge_reasons)
        resolution = self._resolution(decision, case, signals)
        evidence_brief = self._brief(case, risk_score, confidence, decision, signals, edge_reasons)

        return Investigation(
            case_id=case_id,
            risk_score=risk_score,
            confidence=confidence,
            decision=decision,
            resolution=resolution,
            signals=signals,
            edge_reasons=edge_reasons,
            evidence_brief=evidence_brief,
            case=case,
        )

    def investigate_all(self) -> list[Investigation]:
        return [self.investigate(case_id) for case_id in sorted(self.cases)]

    def _collect_signals(self, case: dict[str, Any]) -> list[Signal]:
        signals: list[Signal] = []

        if case["login_country"] != case["usual_country"]:
            signals.append(Signal(
                "Impossible travel or geo drift",
                22,
                f"Login from {case['login_country']} differs from normal {case['usual_country']}.",
                "Account takeover",
            ))

        if case["new_device"]:
            signals.append(Signal(
                "New device at checkout",
                12,
                "Checkout occurred from a device not previously trusted on the account.",
                "Account takeover",
            ))

        if recent(case.get("password_reset_hours_ago"), 24):
            signals.append(Signal(
                "Recent credential reset",
                18,
                f"Password reset {case['password_reset_hours_ago']} hours before transaction.",
                "Account takeover",
            ))

        if recent(case.get("phone_changed_hours_ago"), 24):
            signals.append(Signal(
                "Recent phone change",
                16,
                f"Phone number changed {case['phone_changed_hours_ago']} hours before transaction.",
                "SIM swap or account takeover",
            ))

        if case["address_reuse_count"] >= 10:
            signals.append(Signal(
                "Address reuse cluster",
                17,
                f"Address appears on {case['address_reuse_count']} buyer accounts.",
                "Mule address or reshipping ring",
            ))
        elif case["address_reuse_count"] >= 5:
            signals.append(Signal(
                "Moderate address reuse",
                8,
                f"Address appears on {case['address_reuse_count']} buyer accounts.",
                "Voucher farming or shared drop point",
            ))

        if case["payment_method"] == "cod" and case["cod_failed_count_60d"] >= 5:
            signals.append(Signal(
                "COD refusal pattern",
                23,
                f"{case['cod_failed_count_60d']} failed COD deliveries in 60 days.",
                "Cash-on-delivery abuse",
            ))

        if case["payment_method"] in {"card", "bnpl"} and case["chargeback_count_90d"] > 0:
            signals.append(Signal(
                "Recent payment disputes",
                19,
                f"{case['chargeback_count_90d']} chargeback or dispute events in 90 days.",
                "Payment method abuse",
            ))

        if case["payment_method"] in {"card", "e_wallet", "bnpl"} and (case.get("payment_age_days") or 99) <= 2:
            signals.append(Signal(
                "Fresh payment instrument",
                10,
                f"{case['payment_method']} added {case['payment_age_days']} day(s) ago.",
                "Payment method abuse",
            ))

        if case["voucher_count"] >= 6:
            signals.append(Signal(
                "Promo stacking",
                12,
                f"{case['voucher_count']} vouchers or incentives used in a short window.",
                "Voucher farming",
            ))

        if case["order_value_usd"] >= 1000 and case["category"] in {"phones", "luxury", "gaming"}:
            signals.append(Signal(
                "High-value liquid goods",
                14,
                f"${case['order_value_usd']} order in {case['category']}, easy to resell.",
                "Resale fraud",
            ))

        note = case["support_note"].lower()
        if "did not place" in note:
            signals.append(Signal(
                "Customer denies order",
                30,
                case["support_note"],
                "Confirmed victim report",
            ))

        if "off-platform" in note or "whatsapp" in note:
            signals.append(Signal(
                "Off-platform payment request",
                28,
                case["support_note"],
                "Social-commerce scam",
            ))

        if case["social_seller"] and case["merchant_age_days"] < 14:
            signals.append(Signal(
                "New social seller",
                18,
                f"Seller account is {case['merchant_age_days']} days old.",
                "Seller-side scam",
            ))

        if case["delivery_speed"] in {"same_day", "express"} and case["order_value_usd"] >= 300:
            signals.append(Signal(
                "Urgent fulfillment pressure",
                8,
                f"{case['delivery_speed']} delivery requested for a ${case['order_value_usd']} order.",
                "Fulfillment bypass attempt",
            ))

        if not signals:
            signals.append(Signal(
                "Clean behavioral profile",
                -8,
                "No material anomaly across payment, account, device, logistics, or support evidence.",
                "Low risk",
            ))

        return signals

    def _edge_reasons(self, case: dict[str, Any], signals: list[Signal], risk_score: int) -> list[str]:
        reasons: list[str] = []
        if case["customer_tier"] == "vip" and risk_score >= 35:
            reasons.append("VIP account with non-trivial risk requires human-sensitive handling.")
        if case["order_value_usd"] >= 2000 and 35 <= risk_score < 75:
            reasons.append("High-value order has mixed evidence rather than a clean fraud finding.")
        if 45 <= risk_score <= 60 and len(signals) <= 3:
            reasons.append("Risk score sits in the gray zone with limited corroborating evidence.")
        if case["support_note"].strip() == "":
            reasons.append("Support context is missing.")
        return reasons

    def _confidence(self, case: dict[str, Any], signals: list[Signal], edge_reasons: list[str]) -> float:
        corroboration = len([signal for signal in signals if signal.weight > 0])
        confidence = 0.52 + min(corroboration * 0.07, 0.32)
        if any(signal.weight >= 28 for signal in signals):
            confidence += 0.08
        if edge_reasons:
            confidence -= 0.14
        if case["customer_tier"] == "vip":
            confidence -= 0.04
        return round(max(0.35, min(confidence, 0.96)), 2)

    def _decide(self, case: dict[str, Any], risk_score: int, confidence: float, edge_reasons: list[str]) -> str:
        if edge_reasons and (confidence < 0.78 or case["customer_tier"] == "vip"):
            return "escalate_edge_case"
        if "did not place" in case["support_note"].lower() and risk_score >= 65:
            return "refund_customer"
        if risk_score >= 78 and confidence >= 0.76:
            return "cancel_order"
        if risk_score >= 40:
            return "hold_review"
        return "approve"

    def _resolution(self, decision: str, case: dict[str, Any], signals: list[Signal]) -> list[str]:
        if decision == "approve":
            return ["Approve order", "Continue passive post-fulfillment monitoring"]
        if decision == "hold_review":
            return [
                "Hold fulfillment or payout for up to 24 hours",
                "Trigger step-up verification matched to local channel",
                "Release automatically if verification clears",
            ]
        if decision == "cancel_order":
            return [
                "Cancel before shipment",
                "Block payment instrument, device, and address cluster",
                "Preserve evidence for dispute response",
            ]
        if decision == "refund_customer":
            return [
                "Refund customer and freeze fulfillment",
                "Re-secure account with password reset and device revocation",
                "Create dispute evidence packet",
            ]
        return [
            "Escalate to fraud operations with evidence brief",
            "Keep customer-safe hold active",
            "Ask reviewer to resolve conflicting or sensitive evidence",
        ]

    def _brief(
        self,
        case: dict[str, Any],
        risk_score: int,
        confidence: float,
        decision: str,
        signals: list[Signal],
        edge_reasons: list[str],
    ) -> str:
        top_signals = sorted(signals, key=lambda signal: signal.weight, reverse=True)[:3]
        signal_text = "; ".join(f"{signal.name}: {signal.evidence}" for signal in top_signals)
        edge_text = " Edge constraints: " + " ".join(edge_reasons) if edge_reasons else ""
        return (
            f"kosong_phucs assessed {case['id']} as {risk_score}/100 risk with "
            f"{int(confidence * 100)}% confidence and decision {decision}. "
            f"Key evidence: {signal_text}.{edge_text}"
        )


def recent(hours: Any, window: int) -> bool:
    return hours is not None and hours <= window


def load_cases() -> list[dict[str, Any]]:
    return json.loads(CASE_FILE.read_text(encoding="utf-8"))


def render_dashboard() -> str:
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>kosong_phucs Fraud Agent</title>
  <style>
    :root {
      color-scheme: light;
      --ink: #17211c;
      --muted: #66736d;
      --line: #d9e1dc;
      --bg: #f6f8f5;
      --panel: #ffffff;
      --green: #117a4f;
      --amber: #b7791f;
      --red: #b42318;
      --blue: #2563eb;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: var(--ink);
      background: var(--bg);
    }
    header {
      padding: 28px clamp(18px, 4vw, 48px);
      background: #fff;
      border-bottom: 1px solid var(--line);
      display: flex;
      justify-content: space-between;
      gap: 20px;
      align-items: center;
      flex-wrap: wrap;
    }
    h1 { margin: 0; font-size: clamp(28px, 4vw, 46px); line-height: 1; }
    .tagline { margin: 10px 0 0; color: var(--muted); max-width: 760px; }
    .badge {
      border: 1px solid var(--line);
      background: #f9fbfa;
      border-radius: 999px;
      padding: 8px 12px;
      font-weight: 700;
      color: var(--green);
      white-space: nowrap;
    }
    main {
      display: grid;
      grid-template-columns: minmax(250px, 340px) 1fr;
      gap: 22px;
      padding: 24px clamp(18px, 4vw, 48px);
    }
    aside, section {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      min-width: 0;
    }
    aside { overflow: hidden; }
    .case-button {
      width: 100%;
      padding: 16px;
      text-align: left;
      border: 0;
      border-bottom: 1px solid var(--line);
      background: #fff;
      cursor: pointer;
      color: var(--ink);
    }
    .case-button:hover, .case-button.active { background: #eef7f1; }
    .case-id { font-weight: 800; display: block; }
    .case-meta { color: var(--muted); display: block; margin-top: 4px; }
    .content { padding: 22px; }
    .summary {
      display: grid;
      grid-template-columns: repeat(4, minmax(130px, 1fr));
      gap: 12px;
      margin-bottom: 18px;
    }
    .metric {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
      background: #fbfcfb;
    }
    .label { color: var(--muted); font-size: 13px; }
    .value { font-size: 22px; font-weight: 850; margin-top: 6px; overflow-wrap: anywhere; }
    .risk-low { color: var(--green); }
    .risk-mid { color: var(--amber); }
    .risk-high { color: var(--red); }
    .brief {
      padding: 16px;
      background: #f6f8f5;
      border: 1px solid var(--line);
      border-radius: 8px;
      line-height: 1.5;
    }
    h2 { margin: 22px 0 10px; font-size: 18px; }
    .signals {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
      gap: 12px;
    }
    .signal {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
    }
    .signal strong { display: block; margin-bottom: 6px; }
    .signal span { color: var(--muted); font-size: 14px; line-height: 1.45; }
    .pattern { margin-top: 10px; color: var(--blue); font-weight: 750; font-size: 13px; }
    .actions { margin: 0; padding-left: 20px; line-height: 1.7; }
    @media (max-width: 840px) {
      main { grid-template-columns: 1fr; }
      .summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>kosong_phucs</h1>
      <p class="tagline">Autonomous fraud investigation and resolution for SEA e-commerce: ATO, COD abuse, voucher farming, mule addresses, BNPL abuse, and social-commerce scams.</p>
    </div>
    <div class="badge">Agent demo</div>
  </header>
  <main>
    <aside id="cases"></aside>
    <section>
      <div class="content" id="detail">Loading investigations...</div>
    </section>
  </main>
  <script>
    const casesEl = document.querySelector("#cases");
    const detailEl = document.querySelector("#detail");
    let investigations = [];

    function riskClass(score) {
      if (score >= 70) return "risk-high";
      if (score >= 40) return "risk-mid";
      return "risk-low";
    }

    function decisionLabel(value) {
      return value.split("_").map(word => word[0].toUpperCase() + word.slice(1)).join(" ");
    }

    function renderList(activeId) {
      casesEl.innerHTML = investigations.map(item => `
        <button class="case-button ${item.case_id === activeId ? "active" : ""}" data-id="${item.case_id}">
          <span class="case-id">${item.case_id}</span>
          <span class="case-meta">${item.case.country} · ${item.case.payment_method} · $${item.case.order_value_usd}</span>
        </button>
      `).join("");
      for (const button of casesEl.querySelectorAll("button")) {
        button.addEventListener("click", () => renderDetail(button.dataset.id));
      }
    }

    function renderDetail(id) {
      const item = investigations.find(row => row.case_id === id);
      renderList(id);
      detailEl.innerHTML = `
        <div class="summary">
          <div class="metric"><div class="label">Risk score</div><div class="value ${riskClass(item.risk_score)}">${item.risk_score}/100</div></div>
          <div class="metric"><div class="label">Decision</div><div class="value">${decisionLabel(item.decision)}</div></div>
          <div class="metric"><div class="label">Confidence</div><div class="value">${Math.round(item.confidence * 100)}%</div></div>
          <div class="metric"><div class="label">Pattern count</div><div class="value">${item.signals.length}</div></div>
        </div>
        <div class="brief">${item.evidence_brief}</div>
        <h2>Resolution Actions</h2>
        <ul class="actions">${item.resolution.map(action => `<li>${action}</li>`).join("")}</ul>
        ${item.edge_reasons.length ? `<h2>Escalation Constraints</h2><ul class="actions">${item.edge_reasons.map(reason => `<li>${reason}</li>`).join("")}</ul>` : ""}
        <h2>Evidence Signals</h2>
        <div class="signals">
          ${item.signals.sort((a, b) => b.weight - a.weight).map(signal => `
            <div class="signal">
              <strong>${signal.name} <span class="${riskClass(signal.weight + 40)}">+${signal.weight}</span></strong>
              <span>${signal.evidence}</span>
              <div class="pattern">${signal.pattern}</div>
            </div>
          `).join("")}
        </div>
      `;
    }

    fetch("/api/batch")
      .then(response => response.json())
      .then(data => {
        investigations = data;
        renderDetail(investigations[0].case_id);
      })
      .catch(error => {
        detailEl.textContent = `Could not load investigations: ${error}`;
      });
  </script>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    agent = KosongPhucsAgent(load_cases())

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send(200, render_dashboard(), "text/html")
            return
        if parsed.path == "/api/cases":
            self._json(200, list(self.agent.cases.values()))
            return
        if parsed.path == "/api/batch":
            self._json(200, [item.to_dict() for item in self.agent.investigate_all()])
            return
        if parsed.path == "/api/investigate":
            case_id = parse_qs(parsed.query).get("id", [""])[0]
            if case_id not in self.agent.cases:
                self._json(404, {"error": "unknown case id"})
                return
            self._json(200, self.agent.investigate(case_id).to_dict())
            return
        self._json(404, {"error": "not found"})

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _json(self, status: int, payload: Any) -> None:
        self._send(status, json.dumps(payload, indent=2), "application/json")

    def _send(self, status: int, body: str, content_type: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def print_investigation(investigation: Investigation) -> None:
    print(f"\n{investigation.case_id} | {investigation.decision} | risk {investigation.risk_score}/100 | confidence {int(investigation.confidence * 100)}%")
    print(investigation.evidence_brief)
    print("Resolution:")
    for action in investigation.resolution:
        print(f"  - {action}")
    print("Signals:")
    for signal in sorted(investigation.signals, key=lambda item: item.weight, reverse=True):
        print(f"  - +{signal.weight} {signal.name}: {signal.evidence} [{signal.pattern}]")


def main() -> None:
    parser = argparse.ArgumentParser(description="kosong_phucs SEA fraud investigation agent")
    parser.add_argument("--case", help="Investigate a single case id")
    parser.add_argument("--batch", action="store_true", help="Investigate all cases")
    parser.add_argument("--serve", action="store_true", help="Run the web demo")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()

    agent = KosongPhucsAgent(load_cases())

    if args.serve:
        server = ThreadingHTTPServer((args.host, args.port), Handler)
        print(f"kosong_phucs running at http://{args.host}:{args.port}")
        server.serve_forever()

    if args.case:
        if args.case not in agent.cases:
            raise SystemExit(f"Unknown case id: {args.case}")
        print_investigation(agent.investigate(args.case))
        return

    if args.batch:
        for investigation in agent.investigate_all():
            print_investigation(investigation)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
