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

## Demo Story

1. A case arrives from checkout, post-payment monitoring, or customer support.
2. kosong_phucs gathers evidence from simulated commerce systems:
   account history, login events, payment behavior, device reputation, address reuse, shipment risk, promo behavior, and support notes.
3. It maps signals to SEA-specific fraud patterns.
4. It makes a resolution decision and produces a concise evidence brief.
5. It escalates only edge cases with conflicting evidence, very high value, VIP sensitivity, or insufficient confidence.

## Decisions

- `approve`: risk is low, no action required.
- `hold_review`: temporarily hold fulfillment or payout while a customer-safe verification is performed.
- `cancel_order`: fraud is likely before shipment.
- `refund_customer`: customer appears victimized, often ATO or merchant/social scam.
- `escalate_edge_case`: evidence conflicts or business sensitivity is too high for autonomous handling.

## Files

- `kosong_phucs.py`: agent, CLI, HTTP API, and web UI.
- `data/cases.json`: sample SEA e-commerce fraud scenarios.
