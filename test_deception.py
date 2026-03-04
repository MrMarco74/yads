from yads.modules.deception_detector import DeceptionDetector
import json

detector = DeceptionDetector()
result = detector.run_scan("honeypot.cert.org")
print(json.dumps(result, indent=2))
