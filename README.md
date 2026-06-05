# kosong_phucs

Autonomous SEA e-commerce fraud detection and resolution agent for the Epic Connector hackathon.

kosong_phucs investigates suspicious orders, gathers evidence across account, payment, device, logistics, and marketplace signals, then decides whether to approve, hold, cancel, refund, or escalate. The demo is dependency-free and runs with standard Python.

## Why This Agent

Fraud in SEA commerce often blends payment abuse, account takeover, voucher farming, mule addresses, COD manipulation, and social-commerce scam behavior. kosong_phucs focuses on those regional patterns instead of generic card-fraud rules.

## Run

```powershell
python .\kosong_phucs.py --serve
```

Then open:

```text
http://127.0.0.1:8787
```

Run one investigation in the terminal:

```powershell
python .\kosong_phucs.py --case SG-1024
```

Run all sample cases:

```powershell
python .\kosong_phucs.py --batch
```

Run the device UI scam monitor demo:

```powershell
python .\kosong_phucs.py --device-demo
```

## Demo Story

1. A case arrives from checkout, post-payment monitoring, or customer support.
2. kosong_phucs gathers evidence from simulated commerce systems:
   account history, login events, payment behavior, device reputation, address reuse, shipment risk, promo behavior, and support notes.
3. It maps signals to SEA-specific fraud patterns.
4. It makes a resolution decision and produces a concise evidence brief.
5. It escalates only edge cases with conflicting evidence, very high value, VIP sensitivity, or insufficient confidence.

## Device UI Scam Monitor

kosong_phucs can also act like a device-attached safety agent. A mobile app, browser extension, or checkout wrapper can send visible UI text, the active app, current URL, payment amount, and recent device events to:

```text
POST /api/device-ui
```

Example payload:

```json
{
  "session_id": "DEVICE-SG-404",
  "app_name": "WhatsApp",
  "current_url": "https://sg-paynow-verify.example.com/refund",
  "payment_amount_usd": 680,
  "recent_events": ["new_device_login", "phone_changed"],
  "ui_text": "PayNow transfer required within 10 minutes. Send me the OTP verification code."
}
```

The agent detects scam patterns such as off-platform payment pressure, PayNow/DuitNow/GCash-style irreversible transfer requests, OTP sharing, suspicious refund links, urgency language, high-risk chat commerce, and account takeover events. It can return decisions like `block_payment`, `freeze_session`, `warn_and_step_up`, `monitor`, or `allow`.

The web dashboard now includes a **Run Scam Rescue Demo** button that shows the complete intervention story:

- A live risk decision for the device session.
- A customer-safe warning that tells the user what to avoid.
- A SEA country pattern pack for SG, MY, PH, ID, TH, and VN scam rails.
- A rescue timeline from device event to autonomous action.
- A human escalation packet with reviewer question and top evidence.

## Hackathon Highlights

- **Autonomous action:** blocks payment or freezes session when scam evidence is strong.
- **Explainable evidence:** every decision includes weighted signals and pattern labels.
- **Regional intelligence:** recognizes PayNow, DuitNow, GCash, Maya, QRIS, OVO, DANA, PromptPay, MoMo, ZaloPay, and related scam language.
- **Human-in-the-loop only when needed:** generates a reviewer packet for sensitive or ambiguous cases.
- **No dependency risk:** runs with standard Python for reliable live demos.

## Decisions

- `approve`: risk is low, no action required.
- `hold_review`: temporarily hold fulfillment or payout while a customer-safe verification is performed.
- `cancel_order`: fraud is likely before shipment.
- `refund_customer`: customer appears victimized, often ATO or merchant/social scam.
- `escalate_edge_case`: evidence conflicts or business sensitivity is too high for autonomous handling.

## Files

- `kosong_phucs.py`: agent, CLI, HTTP API, and web UI.
- `data/cases.json`: sample SEA e-commerce fraud scenarios.

