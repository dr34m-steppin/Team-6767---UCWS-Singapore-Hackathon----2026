# Kosong Frauds Hackathon Pitch

## One-Liner

Kosong Frauds is an autonomous SEA e-commerce fraud agent that investigates suspicious orders, explains the evidence, resolves clear cases, and escalates only true edge cases.

## Catchy Name

**Kosong Frauds**: memorable, local-sounding, and instantly tied to the mission: reduce scam losses to zero.

## Problem

SEA commerce fraud is not just stolen cards. Operators deal with account takeover, COD refusal loops, voucher farming, mule addresses, BNPL abuse, social-commerce scams, and payment flows that vary by country. Generic fraud tooling often produces queues, not resolutions.

## Solution

Kosong Frauds performs an autonomous investigation:

1. Gathers evidence from account, payment, device, address, logistics, marketplace, and support signals.
2. Maps those signals to SEA-specific fraud patterns.
3. Scores risk and confidence.
4. Makes a resolution decision.
5. Escalates only when evidence is conflicting, sensitive, high-value, or low-confidence.

## Demo Cases

- `SG-1024`: Account takeover with card abuse, geo drift, fresh device, phone change, and customer denial. Decision: refund customer.
- `ID-3381`: Social-commerce scam with off-platform WhatsApp payment and a new seller. Decision: escalate edge case.
- `PH-7740`: Cash-on-delivery refusal and voucher farming. Decision: hold review.
- `TH-2199`: VIP high-value luxury order with mixed signals. Decision: escalate edge case.
- `MY-5022`: BNPL/payment abuse with device and mule-address signals. Decision: cancel order.

## Why It Wins

- Region-specific fraud knowledge, not generic card scoring.
- Autonomous resolution, not just queue prioritization.
- Transparent evidence packet that a fraud ops reviewer can trust.
- Runs locally with no dependencies, making the demo resilient.

## Future Extensions

- Connect to commerce APIs for live evidence gathering.
- Add LLM-generated customer-safe explanations and reviewer summaries.
- Add feedback learning from chargebacks, courier outcomes, and review decisions.
- Add country-specific policy packs for SG, ID, PH, TH, MY, and VN.
