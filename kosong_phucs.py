#!/usr/bin/env python3
"""
kosong_phucs: autonomous SEA e-commerce fraud detection and resolution agent.

The demo intentionally uses only the Python standard library so it can run
cleanly during a hackathon without dependency installation.
"""

from __future__ import annotations

import argparse
import re
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


@dataclass
class DeviceAssessment:
    session_id: str
    risk_score: int
    confidence: float
    decision: str
    resolution: list[str]
    signals: list[Signal]
    evidence_brief: str
    ui_context: dict[str, Any]

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

    def assess_device_ui(self, payload: dict[str, Any]) -> DeviceAssessment:
        context = normalize_device_payload(payload)
        signals = self._collect_device_signals(context)
        risk_score = max(0, min(100, sum(signal.weight for signal in signals)))
        confidence = self._device_confidence(signals, context)
        decision = self._device_decision(risk_score, confidence, signals)
        resolution = self._device_resolution(decision, signals)
        evidence_brief = self._device_brief(context, risk_score, confidence, decision, signals)

        return DeviceAssessment(
            session_id=context["session_id"],
            risk_score=risk_score,
            confidence=confidence,
            decision=decision,
            resolution=resolution,
            signals=signals,
            evidence_brief=evidence_brief,
            ui_context=context,
        )

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

    def _collect_device_signals(self, context: dict[str, Any]) -> list[Signal]:
        signals: list[Signal] = []
        text = context["text"].lower()
        url = context["current_url"].lower()
        app = context["app_name"].lower()
        events = {event.lower() for event in context["recent_events"]}

        if contains_any(text, ["whatsapp", "telegram", "line", "dm me", "message seller"]) and contains_any(text, ["pay", "transfer", "deposit"]):
            signals.append(Signal(
                "Off-platform payment pressure",
                27,
                "UI text asks the buyer to continue payment or coordination in a messaging channel.",
                "Social-commerce scam",
            ))

        if contains_any(text, ["bank transfer", "paynow", "duitnow", "gcash", "maya", "ovo", "dana", "shopeepay", "qr payment"]):
            signals.append(Signal(
                "Local instant-payment rail requested",
                18,
                "The screen requests a regional instant transfer method with weak buyer protection.",
                "Authorized push payment scam",
            ))

        if contains_any(text, ["urgent", "limited time", "last chance", "pay now", "within 10 minutes", "release order"]):
            signals.append(Signal(
                "Urgency language",
                14,
                "Visible copy pressures the user to act quickly before verifying the counterparty.",
                "Social engineering",
            ))

        if contains_any(text, ["otp", "one-time password", "verification code", "share code", "send me the code"]):
            signals.append(Signal(
                "OTP sharing request",
                32,
                "The UI or chat asks for an OTP or verification code.",
                "Account takeover",
            ))

        if contains_any(text, ["refund fee", "unlock fee", "customs fee", "insurance fee", "processing fee", "deposit first"]):
            signals.append(Signal(
                "Advance-fee language",
                24,
                "The screen asks for a fee or deposit before refund, delivery, or release.",
                "Advance-fee scam",
            ))

        if re.search(r"https?://[^\s]+", text) and contains_any(text, ["login", "verify", "claim", "refund", "wallet"]):
            signals.append(Signal(
                "Suspicious verification link",
                22,
                "A link is paired with login, claim, refund, wallet, or verification language.",
                "Phishing",
            ))

        if url and not trusted_url(url):
            signals.append(Signal(
                "Untrusted commerce URL",
                16,
                f"Current URL is outside known marketplace or payment domains: {context['current_url']}.",
                "Phishing or fake storefront",
            ))

        if context["payment_amount_usd"] >= 500 and contains_any(text, ["transfer", "wallet", "qr", "paynow", "duitnow", "gcash"]):
            signals.append(Signal(
                "High-value irreversible payment",
                16,
                f"Payment amount is ${context['payment_amount_usd']} on an instant-transfer-like flow.",
                "Payment method abuse",
            ))

        if "new_device_login" in events:
            signals.append(Signal(
                "New device login event",
                13,
                "Device telemetry reports a new login shortly before the UI action.",
                "Account takeover",
            ))

        if "password_reset" in events or "phone_changed" in events:
            signals.append(Signal(
                "Recent account recovery event",
                17,
                "Recent password reset or phone change appears before the payment flow.",
                "SIM swap or account takeover",
            ))

        if app in {"whatsapp", "telegram", "line", "facebook marketplace", "instagram"} and contains_any(text, ["seller", "courier", "agent", "payment", "deposit"]):
            signals.append(Signal(
                "High-risk chat commerce surface",
                15,
                f"The active app is {context['app_name']}, where marketplace protections may not apply.",
                "Social-commerce scam",
            ))

        if contains_any(text, ["official store", "platform guarantee", "buyer protection"]) and not contains_any(text, ["transfer outside", "whatsapp", "telegram", "otp"]):
            signals.append(Signal(
                "Buyer-protection cues",
                -8,
                "The UI keeps the user inside a protected marketplace or official checkout flow.",
                "Lower risk",
            ))

        if not signals:
            signals.append(Signal(
                "No scam language detected",
                -6,
                "Visible UI and device context do not contain known high-risk scam patterns.",
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

    def _device_confidence(self, signals: list[Signal], context: dict[str, Any]) -> float:
        corroboration = len([signal for signal in signals if signal.weight > 0])
        confidence = 0.48 + min(corroboration * 0.08, 0.36)
        if any(signal.weight >= 30 for signal in signals):
            confidence += 0.08
        if context["text_length"] < 40:
            confidence -= 0.12
        if context["current_url"]:
            confidence += 0.04
        return round(max(0.35, min(confidence, 0.96)), 2)

    def _device_decision(self, risk_score: int, confidence: float, signals: list[Signal]) -> str:
        patterns = {signal.pattern for signal in signals if signal.weight > 0}
        if "Account takeover" in patterns and risk_score >= 55:
            return "freeze_session"
        if risk_score >= 75 and confidence >= 0.72:
            return "block_payment"
        if risk_score >= 45:
            return "warn_and_step_up"
        if risk_score >= 25:
            return "monitor"
        return "allow"

    def _device_resolution(self, decision: str, signals: list[Signal]) -> list[str]:
        if decision == "block_payment":
            return [
                "Block the payment button before funds leave the protected flow",
                "Show the user a scam warning with the top evidence",
                "Create a fraud case with UI text, URL, app, and device events",
            ]
        if decision == "freeze_session":
            return [
                "Freeze checkout and revoke risky session tokens",
                "Require password reset and fresh MFA from a trusted device",
                "Preserve OTP, URL, and device evidence for fraud operations",
            ]
        if decision == "warn_and_step_up":
            return [
                "Warn the user before payment",
                "Require confirmation that payment stays inside the platform",
                "Escalate automatically if the user proceeds to off-platform transfer",
            ]
        if decision == "monitor":
            return [
                "Allow the interaction but increase telemetry sampling",
                "Watch for OTP, link-click, or off-platform payment transitions",
            ]
        return ["Allow flow", "Keep normal passive monitoring active"]

    def _device_brief(
        self,
        context: dict[str, Any],
        risk_score: int,
        confidence: float,
        decision: str,
        signals: list[Signal],
    ) -> str:
        top_signals = sorted(signals, key=lambda signal: signal.weight, reverse=True)[:3]
        signal_text = "; ".join(f"{signal.name}: {signal.evidence}" for signal in top_signals)
        return (
            f"kosong_phucs assessed device session {context['session_id']} as "
            f"{risk_score}/100 UI scam risk with {int(confidence * 100)}% confidence "
            f"and decision {decision}. Key evidence: {signal_text}."
        )


def recent(hours: Any, window: int) -> bool:
    return hours is not None and hours <= window


def load_cases() -> list[dict[str, Any]]:
    return json.loads(CASE_FILE.read_text(encoding="utf-8"))


def normalize_device_payload(payload: dict[str, Any]) -> dict[str, Any]:
    messages = payload.get("messages", [])
    if isinstance(messages, list):
        message_text = "\n".join(str(message) for message in messages)
    else:
        message_text = str(messages)

    recent_events = payload.get("recent_events", [])
    if not isinstance(recent_events, list):
        recent_events = [str(recent_events)]

    ui_text = "\n".join([
        str(payload.get("ui_text", "")),
        message_text,
        str(payload.get("ocr_text", "")),
    ]).strip()

    return {
        "session_id": str(payload.get("session_id") or "DEVICE-DEMO-001"),
        "app_name": str(payload.get("app_name") or "unknown"),
        "current_url": str(payload.get("current_url") or ""),
        "country": str(payload.get("country") or "SG"),
        "payment_amount_usd": int(payload.get("payment_amount_usd") or 0),
        "recent_events": [str(event) for event in recent_events],
        "text": ui_text,
        "text_length": len(ui_text),
    }


def contains_any(text: str, needles: list[str]) -> bool:
    return any(needle in text for needle in needles)


def trusted_url(url: str) -> bool:
    trusted_domains = [
        "amazon.",
        "lazada.",
        "shopee.",
        "tokopedia.",
        "zalora.",
        "grab.",
        "paynow.",
        "paypal.",
        "stripe.",
        "adyen.",
    ]
    return any(domain in url for domain in trusted_domains)


def sample_device_payload() -> dict[str, Any]:
    return {
        "session_id": "DEVICE-SG-404",
        "country": "SG",
        "app_name": "WhatsApp",
        "current_url": "https://sg-paynow-verify.example.com/refund",
        "payment_amount_usd": 680,
        "recent_events": ["new_device_login", "phone_changed"],
        "ui_text": (
            "Seller: Your order is held. PayNow transfer required within 10 minutes "
            "to release order. Send me the OTP verification code after payment. "
            "Use this refund wallet link: https://sg-paynow-verify.example.com/refund"
        ),
    }


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
    .device-lab {
      margin: 0 clamp(18px, 4vw, 48px) 28px;
      padding: 22px;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
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
    .device-grid {
      display: grid;
      grid-template-columns: minmax(260px, 420px) 1fr;
      gap: 16px;
      align-items: start;
    }
    textarea, input {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      font: inherit;
      margin-bottom: 10px;
      background: #fff;
    }
    textarea { min-height: 190px; resize: vertical; }
    button.primary {
      border: 0;
      border-radius: 8px;
      background: var(--green);
      color: #fff;
      padding: 11px 14px;
      font-weight: 800;
      cursor: pointer;
    }
    .hint { color: var(--muted); font-size: 14px; line-height: 1.45; margin-top: 8px; }
    @media (max-width: 840px) {
      main { grid-template-columns: 1fr; }
      .summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .device-grid { grid-template-columns: 1fr; }
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
  <section class="device-lab">
    <h2>Device UI Scam Monitor</h2>
    <div class="device-grid">
      <div>
        <input id="deviceApp" value="WhatsApp" aria-label="App name">
        <input id="deviceUrl" value="https://sg-paynow-verify.example.com/refund" aria-label="Current URL">
        <input id="deviceAmount" value="680" aria-label="Payment amount">
        <textarea id="deviceText" aria-label="Visible device UI text">Seller: Your order is held. PayNow transfer required within 10 minutes to release order. Send me the OTP verification code after payment. Use this refund wallet link: https://sg-paynow-verify.example.com/refund</textarea>
        <button class="primary" id="analyzeDevice">Analyze Device UI</button>
        <p class="hint">Simulates a mobile app, browser extension, or checkout wrapper sending visible UI text, current URL, payment amount, and device events into the agent.</p>
      </div>
      <div id="deviceResult" class="brief">Device assessment will appear here.</div>
    </div>
  </section>
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

    function renderDeviceAssessment(item) {
      document.querySelector("#deviceResult").innerHTML = `
        <div class="summary">
          <div class="metric"><div class="label">UI scam risk</div><div class="value ${riskClass(item.risk_score)}">${item.risk_score}/100</div></div>
          <div class="metric"><div class="label">Decision</div><div class="value">${decisionLabel(item.decision)}</div></div>
          <div class="metric"><div class="label">Confidence</div><div class="value">${Math.round(item.confidence * 100)}%</div></div>
          <div class="metric"><div class="label">Session</div><div class="value">${item.session_id}</div></div>
        </div>
        <div class="brief">${item.evidence_brief}</div>
        <h2>Device Actions</h2>
        <ul class="actions">${item.resolution.map(action => `<li>${action}</li>`).join("")}</ul>
        <h2>Detected UI Signals</h2>
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

    document.querySelector("#analyzeDevice").addEventListener("click", () => {
      fetch("/api/device-ui", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          session_id: "DEVICE-LIVE-001",
          country: "SG",
          app_name: document.querySelector("#deviceApp").value,
          current_url: document.querySelector("#deviceUrl").value,
          payment_amount_usd: Number(document.querySelector("#deviceAmount").value || 0),
          recent_events: ["new_device_login", "phone_changed"],
          ui_text: document.querySelector("#deviceText").value
        })
      })
        .then(response => response.json())
        .then(renderDeviceAssessment)
        .catch(error => {
          document.querySelector("#deviceResult").textContent = `Could not assess device UI: ${error}`;
        });
    });

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
        if parsed.path == "/api/device-demo":
            self._json(200, self.agent.assess_device_ui(sample_device_payload()).to_dict())
            return
        if parsed.path == "/api/investigate":
            case_id = parse_qs(parsed.query).get("id", [""])[0]
            if case_id not in self.agent.cases:
                self._json(404, {"error": "unknown case id"})
                return
            self._json(200, self.agent.investigate(case_id).to_dict())
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/api/device-ui":
            self._json(404, {"error": "not found"})
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8")
        try:
            payload = json.loads(raw_body or "{}")
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid json"})
            return

        self._json(200, self.agent.assess_device_ui(payload).to_dict())

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


def print_device_assessment(assessment: DeviceAssessment) -> None:
    print(f"\n{assessment.session_id} | {assessment.decision} | UI scam risk {assessment.risk_score}/100 | confidence {int(assessment.confidence * 100)}%")
    print(assessment.evidence_brief)
    print("Device actions:")
    for action in assessment.resolution:
        print(f"  - {action}")
    print("Signals:")
    for signal in sorted(assessment.signals, key=lambda item: item.weight, reverse=True):
        print(f"  - +{signal.weight} {signal.name}: {signal.evidence} [{signal.pattern}]")


def main() -> None:
    parser = argparse.ArgumentParser(description="kosong_phucs SEA fraud investigation agent")
    parser.add_argument("--case", help="Investigate a single case id")
    parser.add_argument("--batch", action="store_true", help="Investigate all cases")
    parser.add_argument("--device-demo", action="store_true", help="Assess a suspicious device UI scam flow")
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

    if args.device_demo:
        print_device_assessment(agent.assess_device_ui(sample_device_payload()))
        return

    parser.print_help()


if __name__ == "__main__":
    main()
