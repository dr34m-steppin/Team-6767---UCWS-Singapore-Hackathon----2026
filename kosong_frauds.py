#!/usr/bin/env python3
"""
Kosong Frauds: autonomous SEA e-commerce fraud detection and resolution agent.

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
    timeline: list[dict[str, str]]
    customer_message: str
    reviewer_packet: dict[str, Any]
    country_pack: dict[str, Any]
    ui_context: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        output = asdict(self)
        output["signals"] = [asdict(signal) for signal in self.signals]
        return output


class KosongFraudsAgent:
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
        timeline = self._device_timeline(context, signals, decision)
        customer_message = self._customer_message(decision, signals, context)
        reviewer_packet = self._reviewer_packet(context, risk_score, confidence, decision, signals, resolution)
        country_pack = sea_pattern_pack(context["country"])

        return DeviceAssessment(
            session_id=context["session_id"],
            risk_score=risk_score,
            confidence=confidence,
            decision=decision,
            resolution=resolution,
            signals=signals,
            evidence_brief=evidence_brief,
            timeline=timeline,
            customer_message=customer_message,
            reviewer_packet=reviewer_packet,
            country_pack=country_pack,
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
        country_pack = sea_pattern_pack(context["country"])

        matched_terms = [term for term in country_pack["payment_rails"] if term.lower() in text]
        if matched_terms:
            signals.append(Signal(
                f"{country_pack['country']} payment rail match",
                12,
                f"Matched local payment terms: {', '.join(matched_terms)}.",
                country_pack["primary_risk"],
            ))

        matched_scam_terms = [term for term in country_pack["scam_terms"] if term.lower() in text]
        if matched_scam_terms:
            signals.append(Signal(
                f"{country_pack['country']} scam-language match",
                10,
                f"Matched local scam terms: {', '.join(matched_scam_terms)}.",
                country_pack["primary_risk"],
            ))

        if contains_any(text, ["whatsapp", "telegram", "line", "dm me", "message seller"]) and contains_any(text, ["pay", "transfer", "deposit"]):
            signals.append(Signal(
                "Off-platform payment pressure",
                27,
                "UI text asks the buyer to continue payment or coordination in a messaging channel.",
                "Social-commerce scam",
            ))

        if contains_any(text, ["bank transfer", "paynow", "duitnow", "gcash", "maya", "ovo", "dana", "shopeepay", "qr payment", "qris", "promptpay", "momo", "zalopay", "touch n go"]):
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

        if app in {"whatsapp", "telegram", "line", "facebook marketplace", "instagram", "zalo"} and contains_any(text, ["seller", "courier", "agent", "payment", "deposit"]):
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
            f"Kosong Frauds assessed {case['id']} as {risk_score}/100 risk with "
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
            f"Kosong Frauds assessed device session {context['session_id']} as "
            f"{risk_score}/100 UI scam risk with {int(confidence * 100)}% confidence "
            f"and decision {decision}. Key evidence: {signal_text}."
        )

    def _device_timeline(
        self,
        context: dict[str, Any],
        signals: list[Signal],
        decision: str,
    ) -> list[dict[str, str]]:
        timeline: list[dict[str, str]] = []
        for event in context["recent_events"]:
            timeline.append({
                "stage": "Device event",
                "detail": event.replace("_", " ").title(),
            })
        if context["current_url"]:
            timeline.append({
                "stage": "Navigation",
                "detail": f"User is on {context['current_url']}",
            })
        if context["payment_amount_usd"] > 0:
            timeline.append({
                "stage": "Payment intent",
                "detail": f"Detected payment amount ${context['payment_amount_usd']}",
            })
        for signal in sorted(signals, key=lambda item: item.weight, reverse=True)[:4]:
            if signal.weight > 0:
                timeline.append({
                    "stage": signal.pattern,
                    "detail": f"{signal.name}: {signal.evidence}",
                })
        timeline.append({
            "stage": "Autonomous action",
            "detail": f"Decision: {decision.replace('_', ' ')}",
        })
        return timeline

    def _customer_message(self, decision: str, signals: list[Signal], context: dict[str, Any]) -> str:
        if decision in {"block_payment", "freeze_session"}:
            return (
                "We blocked this payment because the screen shows scam indicators: "
                f"{customer_signal_summary(signals)}. Do not share OTPs or pay outside the "
                "platform. Stay in the official checkout and contact support if you still want this order reviewed."
            )
        if decision == "warn_and_step_up":
            return (
                "This payment looks risky. Keep payment inside the official platform, do not share verification codes, "
                "and verify the seller before continuing."
            )
        if decision == "monitor":
            return "This flow has mild risk. Continue only if the URL, seller, and payment method are expected."
        return "No strong scam indicators were found. Continue using normal buyer-safety checks."

    def _reviewer_packet(
        self,
        context: dict[str, Any],
        risk_score: int,
        confidence: float,
        decision: str,
        signals: list[Signal],
        resolution: list[str],
    ) -> dict[str, Any]:
        positive_signals = [signal for signal in sorted(signals, key=lambda item: item.weight, reverse=True) if signal.weight > 0]
        return {
            "summary": f"{context['session_id']} scored {risk_score}/100 with decision {decision}.",
            "country": context["country"],
            "app": context["app_name"],
            "url": context["current_url"] or "not provided",
            "amount_usd": context["payment_amount_usd"],
            "confidence": confidence,
            "top_evidence": [f"{signal.name}: {signal.evidence}" for signal in positive_signals[:5]],
            "recommended_actions": resolution,
            "reviewer_question": reviewer_question(decision),
            "customer_safe_message": self._customer_message(decision, signals, context),
        }


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


def sea_pattern_pack(country: str) -> dict[str, Any]:
    packs = {
        "SG": {
            "country": "Singapore",
            "payment_rails": ["PayNow", "PayLah", "FAST transfer"],
            "scam_terms": ["Carousell", "refund wallet", "delivery release", "Singpass"],
            "primary_risk": "PayNow or marketplace impersonation scam",
            "safe_instruction": "Keep payment inside the marketplace or official checkout; never share OTP or Singpass codes.",
        },
        "MY": {
            "country": "Malaysia",
            "payment_rails": ["DuitNow", "Touch n Go", "FPX"],
            "scam_terms": ["mule account", "unlock fee", "courier fee"],
            "primary_risk": "DuitNow transfer or mule-account scam",
            "safe_instruction": "Verify merchant identity and avoid direct transfers to personal accounts.",
        },
        "PH": {
            "country": "Philippines",
            "payment_rails": ["GCash", "Maya", "bank transfer"],
            "scam_terms": ["reservation fee", "COD failed", "rider fee"],
            "primary_risk": "GCash/Maya seller scam or COD abuse",
            "safe_instruction": "Use protected checkout and confirm seller reputation before sending wallet funds.",
        },
        "ID": {
            "country": "Indonesia",
            "payment_rails": ["QRIS", "OVO", "DANA", "GoPay"],
            "scam_terms": ["admin fee", "refund link", "WhatsApp seller"],
            "primary_risk": "QRIS or wallet social-commerce scam",
            "safe_instruction": "Avoid WhatsApp payment redirects and verify QRIS merchant identity.",
        },
        "TH": {
            "country": "Thailand",
            "payment_rails": ["PromptPay", "TrueMoney", "bank transfer"],
            "scam_terms": ["deposit", "delivery agent", "refund code"],
            "primary_risk": "PromptPay transfer or social seller scam",
            "safe_instruction": "Confirm payment recipient and avoid seller-provided verification links.",
        },
        "VN": {
            "country": "Vietnam",
            "payment_rails": ["MoMo", "ZaloPay", "bank transfer"],
            "scam_terms": ["shipping fee", "deposit", "verification link"],
            "primary_risk": "Wallet transfer or fake logistics scam",
            "safe_instruction": "Do not pay extra logistics or verification fees outside the platform.",
        },
    }
    return packs.get(country.upper(), {
        "country": country.upper() or "SEA",
        "payment_rails": ["bank transfer", "wallet", "QR payment"],
        "scam_terms": ["deposit", "refund link", "verification code"],
        "primary_risk": "Regional instant-payment scam",
        "safe_instruction": "Keep payment inside a protected checkout and do not share OTPs.",
    })


def customer_signal_summary(signals: list[Signal]) -> str:
    names = [signal.name for signal in sorted(signals, key=lambda item: item.weight, reverse=True) if signal.weight > 0]
    return ", ".join(names[:3]) if names else "unusual payment and device behavior"


def reviewer_question(decision: str) -> str:
    if decision == "freeze_session":
        return "Confirm whether account recovery and device-login evidence indicate takeover before restoring access."
    if decision == "block_payment":
        return "Confirm whether the blocked payment recipient is a legitimate merchant or a mule account."
    if decision == "warn_and_step_up":
        return "Review if the user continued toward off-platform payment after the warning."
    return "Review only if later telemetry adds stronger scam evidence."


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
  <title>Kosong Frauds Agent</title>
  <style>
    :root {
      color-scheme: dark;
      --ink: #f3f7fb;
      --muted: #9aa7b6;
      --line: rgba(148, 163, 184, 0.22);
      --bg: #070b12;
      --panel: rgba(15, 23, 42, 0.86);
      --panel-strong: rgba(20, 30, 49, 0.96);
      --green: #35e0a1;
      --amber: #f8c35b;
      --red: #ff5c72;
      --blue: #6aa6ff;
      --glow: rgba(53, 224, 161, 0.18);
      --shadow: 0 18px 48px rgba(0, 0, 0, 0.36);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(53, 224, 161, 0.16), transparent 34%),
        radial-gradient(circle at 80% 12%, rgba(106, 166, 255, 0.16), transparent 30%),
        linear-gradient(145deg, #070b12 0%, #0b1020 48%, #111827 100%);
      min-height: 100vh;
    }
    header {
      padding: 30px clamp(18px, 4vw, 48px);
      background: rgba(7, 11, 18, 0.76);
      border-bottom: 1px solid var(--line);
      display: flex;
      justify-content: space-between;
      gap: 20px;
      align-items: center;
      flex-wrap: wrap;
      backdrop-filter: blur(18px);
      position: sticky;
      top: 0;
      z-index: 5;
    }
    h1 {
      margin: 0;
      font-size: clamp(30px, 4vw, 52px);
      line-height: 1;
      letter-spacing: 0;
      background: linear-gradient(90deg, #ffffff, #9ff7d7 56%, #8fbaff);
      -webkit-background-clip: text;
      color: transparent;
    }
    .tagline { margin: 10px 0 0; color: var(--muted); max-width: 820px; line-height: 1.55; }
    .badge {
      border: 1px solid rgba(53, 224, 161, 0.36);
      background: rgba(53, 224, 161, 0.1);
      border-radius: 999px;
      padding: 9px 13px;
      font-weight: 800;
      color: var(--green);
      white-space: nowrap;
      box-shadow: 0 0 28px var(--glow);
    }
    main {
      display: grid;
      grid-template-columns: minmax(250px, 340px) 1fr;
      gap: 22px;
      padding: 24px clamp(18px, 4vw, 48px);
    }
    .device-lab {
      margin: 0 clamp(18px, 4vw, 48px) 32px;
      padding: 22px;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 12px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(16px);
    }
    aside, section {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 12px;
      min-width: 0;
      box-shadow: var(--shadow);
      backdrop-filter: blur(16px);
    }
    aside { overflow: hidden; }
    .case-button {
      width: 100%;
      padding: 16px;
      text-align: left;
      border: 0;
      border-bottom: 1px solid var(--line);
      background: transparent;
      cursor: pointer;
      color: var(--ink);
      transition: background 160ms ease, transform 160ms ease;
    }
    .case-button:hover, .case-button.active { background: rgba(53, 224, 161, 0.1); }
    .case-button:hover { transform: translateX(2px); }
    .case-id { font-weight: 850; display: block; }
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
      border-radius: 10px;
      padding: 14px;
      background: linear-gradient(180deg, rgba(255, 255, 255, 0.06), rgba(255, 255, 255, 0.025));
    }
    .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }
    .value { font-size: 22px; font-weight: 900; margin-top: 6px; overflow-wrap: anywhere; }
    .risk-low { color: var(--green); }
    .risk-mid { color: var(--amber); }
    .risk-high { color: var(--red); }
    .brief {
      padding: 16px;
      background: rgba(15, 23, 42, 0.72);
      border: 1px solid var(--line);
      border-radius: 10px;
      line-height: 1.55;
    }
    h2 { margin: 24px 0 10px; font-size: 17px; letter-spacing: 0; }
    .signals {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
      gap: 12px;
    }
    .signal {
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 14px;
      background: rgba(2, 6, 23, 0.36);
    }
    .signal strong { display: block; margin-bottom: 6px; }
    .signal span { color: var(--muted); font-size: 14px; line-height: 1.45; }
    .pattern { margin-top: 10px; color: var(--blue); font-weight: 800; font-size: 13px; }
    .actions { margin: 0; padding-left: 20px; line-height: 1.7; color: #d8e2ee; }
    .device-grid {
      display: grid;
      grid-template-columns: minmax(260px, 420px) 1fr;
      gap: 16px;
      align-items: start;
    }
    textarea, input, select {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 12px;
      font: inherit;
      margin-bottom: 10px;
      background: rgba(2, 6, 23, 0.56);
      color: var(--ink);
      outline: none;
    }
    textarea:focus, input:focus, select:focus { border-color: rgba(53, 224, 161, 0.68); box-shadow: 0 0 0 3px rgba(53, 224, 161, 0.12); }
    select option { background: #0f172a; color: var(--ink); }
    textarea { min-height: 190px; resize: vertical; }
    button.primary {
      border: 0;
      border-radius: 10px;
      background: linear-gradient(135deg, #21c98b, #4ee7b0);
      color: #03120c;
      padding: 12px 15px;
      font-weight: 900;
      cursor: pointer;
      box-shadow: 0 12px 30px rgba(53, 224, 161, 0.18);
    }
    .hint { color: var(--muted); font-size: 14px; line-height: 1.45; margin-top: 8px; }
    .button-row { display: flex; gap: 10px; flex-wrap: wrap; }
    .secondary { border: 1px solid rgba(106, 166, 255, 0.42); border-radius: 10px; background: rgba(106, 166, 255, 0.1); color: #dbeafe; padding: 12px 15px; font-weight: 900; cursor: pointer; }
    .message { border-left: 4px solid var(--red); background: rgba(255, 92, 114, 0.1); padding: 14px; border-radius: 10px; line-height: 1.55; }
    .judge-mode {
      display: grid;
      grid-template-columns: minmax(260px, 360px) 1fr;
      gap: 16px;
      margin-bottom: 18px;
      align-items: stretch;
    }
    .phone {
      border: 1px solid rgba(148, 163, 184, 0.28);
      border-radius: 28px;
      padding: 14px;
      background: linear-gradient(180deg, #111827, #020617);
      box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.04), 0 20px 48px rgba(0, 0, 0, 0.42);
      min-height: 520px;
    }
    .phone-top { display: flex; justify-content: space-between; color: #cbd5e1; font-size: 12px; padding: 4px 10px 12px; }
    .phone-screen { border-radius: 20px; overflow: hidden; background: #07111f; min-height: 472px; border: 1px solid rgba(148, 163, 184, 0.18); }
    .chat-head { padding: 14px; background: rgba(15, 23, 42, 0.92); border-bottom: 1px solid var(--line); }
    .chat-title { font-weight: 900; }
    .chat-sub { color: var(--muted); font-size: 12px; margin-top: 3px; }
    .chat-body { padding: 14px; display: grid; gap: 10px; }
    .bubble { padding: 12px; border-radius: 14px; line-height: 1.45; font-size: 14px; }
    .seller { background: rgba(106, 166, 255, 0.12); border: 1px solid rgba(106, 166, 255, 0.18); }
    .system { background: rgba(255, 92, 114, 0.12); border: 1px solid rgba(255, 92, 114, 0.24); }
    .pay-card { margin-top: 8px; border: 1px solid rgba(53, 224, 161, 0.24); border-radius: 14px; padding: 12px; background: rgba(53, 224, 161, 0.08); }
    .blocked-stamp { margin-top: 12px; border-radius: 12px; padding: 12px; background: rgba(255, 92, 114, 0.18); border: 1px solid rgba(255, 92, 114, 0.38); color: #ffd4da; font-weight: 900; text-align: center; }
    .impact-grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(130px, 1fr));
      gap: 12px;
      margin: 14px 0 18px;
    }
    .impact-card {
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 14px;
      background: rgba(2, 6, 23, 0.36);
    }
    .impact-card strong { display: block; font-size: 22px; margin-top: 5px; }
    .demo-note { color: var(--muted); line-height: 1.55; margin: 0 0 14px; }
    .timeline { display: grid; gap: 10px; }
    .timeline-step { border: 1px solid var(--line); border-radius: 10px; padding: 12px; background: rgba(15, 23, 42, 0.66); }
    .timeline-step strong { display: block; margin-bottom: 4px; color: var(--green); }
    .packet { display: grid; gap: 8px; }
    .packet-row { border-bottom: 1px solid var(--line); padding-bottom: 8px; line-height: 1.45; }
    @media (max-width: 840px) {
      header { position: static; }
      main { grid-template-columns: 1fr; }
      .summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .device-grid { grid-template-columns: 1fr; }
      .judge-mode { grid-template-columns: 1fr; }
      .impact-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>Kosong Frauds</h1>
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
    <h2>Judge Demo Mode: Scam Rescue</h2>
    <p class="demo-note">Run a live-looking device intervention: the user is pushed into an irreversible local payment, Kosong Frauds detects the scam, blocks the payment, warns the customer, and creates an ops packet.</p>
    <div class="judge-mode">
      <div class="phone" aria-label="Simulated phone UI">
        <div class="phone-top"><span>9:41</span><span id="phoneCountry">SG</span></div>
        <div class="phone-screen">
          <div class="chat-head">
            <div class="chat-title" id="phoneApp">WhatsApp</div>
            <div class="chat-sub">Marketplace seller chat</div>
          </div>
          <div class="chat-body">
            <div class="bubble seller" id="phoneText">Seller: Your order is held. PayNow transfer required within 10 minutes to release order. Send me the OTP verification code after payment.</div>
            <div class="pay-card">
              <div class="label">Payment request</div>
              <div class="value" id="phoneAmount">$680</div>
              <div class="case-meta" id="phoneUrl">sg-paynow-verify.example.com/refund</div>
            </div>
            <div class="blocked-stamp" id="phoneStatus">Awaiting agent decision</div>
          </div>
        </div>
      </div>
      <div>
        <div class="impact-grid" id="impactGrid">
          <div class="impact-card"><span class="label">Without agent</span><strong class="risk-high">$680 lost</strong></div>
          <div class="impact-card"><span class="label">With agent</span><strong class="risk-low">$680 saved</strong></div>
          <div class="impact-card"><span class="label">Ops time</span><strong>18 min saved</strong></div>
          <div class="impact-card"><span class="label">Escalation</span><strong>Not needed</strong></div>
        </div>
        <input id="deviceApp" value="WhatsApp" aria-label="App name">
        <select id="deviceCountry" aria-label="Country code">
          <option value="SG">Singapore: PayNow / Singpass</option>
          <option value="MY">Malaysia: DuitNow / mule account</option>
          <option value="PH">Philippines: GCash / Maya</option>
          <option value="ID">Indonesia: QRIS / OVO / DANA</option>
          <option value="TH">Thailand: PromptPay</option>
          <option value="VN">Vietnam: MoMo / ZaloPay</option>
        </select>
        <input id="deviceUrl" value="https://sg-paynow-verify.example.com/refund" aria-label="Current URL">
        <input id="deviceAmount" value="680" aria-label="Payment amount">
        <textarea id="deviceText" aria-label="Visible device UI text">Seller: Your order is held. PayNow transfer required within 10 minutes to release order. Send me the OTP verification code after payment. Use this refund wallet link: https://sg-paynow-verify.example.com/refund</textarea>
        <div class="button-row">
          <button class="primary" id="analyzeDevice">Analyze Device UI</button>
          <button class="secondary" id="runRescueDemo">Run Scam Rescue Demo</button>
        </div>
        <p class="hint">Simulates a mobile app, browser extension, or checkout wrapper sending visible UI text, current URL, payment amount, and device events into the agent.</p>
      </div>
    </div>
    <div id="deviceResult" class="brief">Device assessment will appear here.</div>
  </section>
  <script>
    const casesEl = document.querySelector("#cases");
    const detailEl = document.querySelector("#detail");
    let investigations = [];
    const countryProfiles = {
      SG: {
        app: "WhatsApp",
        amount: 680,
        url: "https://sg-paynow-verify.example.com/refund",
        rail: "PayNow",
        loss: "$680 lost",
        saved: "$680 saved",
        ops: "18 min saved",
        text: "Seller: Your order is held. PayNow transfer required within 10 minutes to release order. Send me the OTP verification code after payment. Use this refund wallet link: https://sg-paynow-verify.example.com/refund"
      },
      MY: {
        app: "Telegram",
        amount: 420,
        url: "https://duitnow-release.example.com/verify",
        rail: "DuitNow",
        loss: "$420 lost",
        saved: "$420 saved",
        ops: "16 min saved",
        text: "Courier agent: DuitNow transfer to this mule account is required before delivery. Pay now, then send the verification code so we can unlock your parcel."
      },
      PH: {
        app: "Facebook Marketplace",
        amount: 310,
        url: "https://gcash-refund.example.com/wallet",
        rail: "GCash",
        loss: "$310 lost",
        saved: "$310 saved",
        ops: "14 min saved",
        text: "Seller: Pay the GCash reservation fee now or the item goes to another buyer. Use this refund wallet link and share the OTP after payment."
      },
      ID: {
        app: "WhatsApp",
        amount: 530,
        url: "https://qris-wallet-claim.example.com/login",
        rail: "QRIS",
        loss: "$530 lost",
        saved: "$530 saved",
        ops: "19 min saved",
        text: "Admin: Scan this QRIS payment now to release your order. OVO or DANA accepted. Login to the refund link and send your verification code."
      },
      TH: {
        app: "LINE",
        amount: 760,
        url: "https://promptpay-agent.example.com/refund-code",
        rail: "PromptPay",
        loss: "$760 lost",
        saved: "$760 saved",
        ops: "21 min saved",
        text: "Delivery agent: PromptPay deposit required urgently before customs release. Send refund code and OTP within 10 minutes to avoid cancellation."
      },
      VN: {
        app: "Zalo",
        amount: 260,
        url: "https://momo-shipping.example.com/verify",
        rail: "MoMo",
        loss: "$260 lost",
        saved: "$260 saved",
        ops: "12 min saved",
        text: "Seller: MoMo shipping fee deposit required first. Open this verification link and share the code so ZaloPay refund can be processed."
      }
    };

    function riskClass(score) {
      if (score >= 70) return "risk-high";
      if (score >= 40) return "risk-mid";
      return "risk-low";
    }

    function decisionLabel(value) {
      return value.split("_").map(word => word[0].toUpperCase() + word.slice(1)).join(" ");
    }

    function selectedProfile() {
      const country = document.querySelector("#deviceCountry").value || "SG";
      return { country, ...countryProfiles[country] };
    }

    function updatePhone(statusText = "Awaiting agent decision", blocked = false) {
      const profile = selectedProfile();
      document.querySelector("#phoneCountry").textContent = profile.country;
      document.querySelector("#phoneApp").textContent = profile.app;
      document.querySelector("#phoneText").textContent = profile.text;
      document.querySelector("#phoneAmount").textContent = `$${profile.amount}`;
      document.querySelector("#phoneUrl").textContent = profile.url.replace("https://", "");
      const status = document.querySelector("#phoneStatus");
      status.textContent = statusText;
      status.style.borderColor = blocked ? "rgba(255, 92, 114, 0.48)" : "rgba(53, 224, 161, 0.34)";
    }

    function updateImpact(assessment = null) {
      const profile = selectedProfile();
      const decision = assessment ? decisionLabel(assessment.decision) : "Pending";
      const escalated = assessment && assessment.decision.includes("escalate") ? "Human review" : "Not needed";
      document.querySelector("#impactGrid").innerHTML = `
        <div class="impact-card"><span class="label">Without agent</span><strong class="risk-high">${profile.loss}</strong></div>
        <div class="impact-card"><span class="label">With agent</span><strong class="risk-low">${profile.saved}</strong></div>
        <div class="impact-card"><span class="label">Ops time</span><strong>${profile.ops}</strong></div>
        <div class="impact-card"><span class="label">Autonomous decision</span><strong>${assessment ? decision : escalated}</strong></div>
      `;
    }

    function applyCountryProfile() {
      const profile = selectedProfile();
      document.querySelector("#deviceApp").value = profile.app;
      document.querySelector("#deviceUrl").value = profile.url;
      document.querySelector("#deviceAmount").value = profile.amount;
      document.querySelector("#deviceText").value = profile.text;
      updatePhone();
      updateImpact();
    }

    function collectDevicePayload(sessionId) {
      return {
        session_id: sessionId,
        country: document.querySelector("#deviceCountry").value || "SG",
        app_name: document.querySelector("#deviceApp").value,
        current_url: document.querySelector("#deviceUrl").value,
        payment_amount_usd: Number(document.querySelector("#deviceAmount").value || 0),
        recent_events: ["new_device_login", "phone_changed"],
        ui_text: document.querySelector("#deviceText").value
      };
    }

    function renderList(activeId) {
      casesEl.innerHTML = investigations.map(item => `
        <button class="case-button ${item.case_id === activeId ? "active" : ""}" data-id="${item.case_id}">
          <span class="case-id">${item.case_id}</span>
          <span class="case-meta">${item.case.country} &middot; ${item.case.payment_method} &middot; $${item.case.order_value_usd}</span>
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
      updatePhone(`Blocked by Kosong Frauds: ${decisionLabel(item.decision)}`, true);
      updateImpact(item);
      document.querySelector("#deviceResult").innerHTML = `
        <div class="summary">
          <div class="metric"><div class="label">UI scam risk</div><div class="value ${riskClass(item.risk_score)}">${item.risk_score}/100</div></div>
          <div class="metric"><div class="label">Decision</div><div class="value">${decisionLabel(item.decision)}</div></div>
          <div class="metric"><div class="label">Confidence</div><div class="value">${Math.round(item.confidence * 100)}%</div></div>
          <div class="metric"><div class="label">Session</div><div class="value">${item.session_id}</div></div>
        </div>
        <div class="brief">${item.evidence_brief}</div>
        <h2>Customer Warning</h2>
        <div class="message">${item.customer_message}</div>
        <h2>SEA Pattern Pack</h2>
        <div class="brief"><strong>${item.country_pack.country}</strong>: ${item.country_pack.primary_risk}<br>${item.country_pack.safe_instruction}</div>
        <h2>Rescue Timeline</h2>
        <div class="timeline">
          ${item.timeline.map(step => `<div class="timeline-step"><strong>${step.stage}</strong><span>${step.detail}</span></div>`).join("")}
        </div>
        <h2>Device Actions</h2>
        <ul class="actions">${item.resolution.map(action => `<li>${action}</li>`).join("")}</ul>
        <h2>Human Escalation Packet</h2>
        <div class="packet">
          <div class="packet-row"><strong>Summary:</strong> ${item.reviewer_packet.summary}</div>
          <div class="packet-row"><strong>Reviewer question:</strong> ${item.reviewer_packet.reviewer_question}</div>
          <div class="packet-row"><strong>Top evidence:</strong> ${item.reviewer_packet.top_evidence.join("; ")}</div>
        </div>
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
      updatePhone("Analyzing visible UI and device events...", false);
      fetch("/api/device-ui", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(collectDevicePayload("DEVICE-LIVE-001"))
      })
        .then(response => response.json())
        .then(renderDeviceAssessment)
        .catch(error => {
          document.querySelector("#deviceResult").textContent = `Could not assess device UI: ${error}`;
        });
    });

    document.querySelector("#runRescueDemo").addEventListener("click", () => {
      applyCountryProfile();
      updatePhone("Scam pressure detected. Running autonomous rescue...", false);
      fetch("/api/device-ui", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(collectDevicePayload(`DEVICE-${document.querySelector("#deviceCountry").value}-RESCUE`))
      })
        .then(response => response.json())
        .then(renderDeviceAssessment)
        .catch(error => {
          document.querySelector("#deviceResult").textContent = `Could not run rescue demo: ${error}`;
        });
    });

    document.querySelector("#deviceCountry").addEventListener("change", applyCountryProfile);
    applyCountryProfile();
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
    agent = KosongFraudsAgent(load_cases())

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
    print("\nCustomer-safe message:")
    print(f"  {assessment.customer_message}")
    print("\nCountry pattern pack:")
    print(f"  {assessment.country_pack['country']}: {assessment.country_pack['primary_risk']}")
    print(f"  Safe instruction: {assessment.country_pack['safe_instruction']}")
    print("\nRescue timeline:")
    for step in assessment.timeline:
        print(f"  - {step['stage']}: {step['detail']}")
    print("\nDevice actions:")
    for action in assessment.resolution:
        print(f"  - {action}")
    print("\nReviewer packet:")
    print(f"  {assessment.reviewer_packet['summary']}")
    print(f"  Question: {assessment.reviewer_packet['reviewer_question']}")
    print("\nSignals:")
    for signal in sorted(assessment.signals, key=lambda item: item.weight, reverse=True):
        print(f"  - +{signal.weight} {signal.name}: {signal.evidence} [{signal.pattern}]")


def main() -> None:
    parser = argparse.ArgumentParser(description="Kosong Frauds SEA fraud investigation agent")
    parser.add_argument("--case", help="Investigate a single case id")
    parser.add_argument("--batch", action="store_true", help="Investigate all cases")
    parser.add_argument("--device-demo", action="store_true", help="Assess a suspicious device UI scam flow")
    parser.add_argument("--serve", action="store_true", help="Run the web demo")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()

    agent = KosongFraudsAgent(load_cases())

    if args.serve:
        server = ThreadingHTTPServer((args.host, args.port), Handler)
        print(f"Kosong Frauds running at http://{args.host}:{args.port}")
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









