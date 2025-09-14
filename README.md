# SecureEdge

Concept

SecureEdge is an on-device privacy and safety co-pilot for laptops. It runs fully offline on CPU/NPU and quietly monitors two things in real time: (1) the webcam for suspicious motion near the screen, and (2) the clipboard for sensitive text. When risk is detected (e.g., a person leans into frame, or you paste an API key/JWT/credit card), SecureEdge reacts instantly—warning the user, and redacting secrets before they reach other apps. Everything stays on device; no cloud calls, no data saved.

Features
	•	Suspicious Motion Detector (built): Uses the webcam (no cloud) to raise a risk score for edge-to-center motion, new faces/extra faces, and rapid proximity changes. Shows a small HUD (green/amber/red) and can trigger blur/lock actions.
	•	Object Detection (built): Runs a lightweight detector to spot items of concern (e.g., a phone held up toward the screen) and boosts the risk score.
	•	PasteGuard (built): Intercepts ⌘/Ctrl+V; an on-device instruction model returns strict JSON spans for secrets (API keys, JWTs, credit cards, passwords). Only those spans are masked (keep-last-4 or full), then the original clipboard is restored—so UX stays smooth.
	•	Runs 100% offline: Uses Qualcomm-optimized, on-device models (e.g., a small instruct LLM for JSON labeling and an edge vision model) so it works without internet.

What we used
	•	Vision: Lightweight on-device detector for person/phone + simple motion heuristics (edge-in, proximity change).
	•	Text privacy: A small instruction-tuned LLM from Qualcomm AI Hub (GenAI bundle) to classify clipboard text and return {is_secret, spans[]}.
	•	System glue: Keyboard/clipboard hooks for paste interception, minimal HUD/toast UI, and local policy config.
