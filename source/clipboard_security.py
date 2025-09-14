#!/usr/bin/env python3
"""
Phi-3.5-Mini Clipboard Security for Qualcomm Edge AI Hackathon
Detects and redacts sensitive information in clipboard content
"""

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
import pyperclip
import re
import threading
import time
import json
import hashlib
from typing import Dict, List, Optional
import sys

class PhiClipboardSecurity:
    def __init__(self):
        """Initialize Phi-3.5-Mini for clipboard security"""
        print("🚀 Starting Phi-3.5-Mini Clipboard Security")
        print("=" * 50)
        
        try:
            self._load_model()
            self._setup_patterns()
            self.monitoring = False
            self.last_hash = None
            print("✅ Security system ready!")
        except Exception as e:
            print(f"❌ Initialization failed: {e}")
            sys.exit(1)

    def _load_model(self):
        """Load Phi-3.5-Mini model and tokenizer"""
        print("🤖 Loading Phi-3.5-Mini-Instruct...")
        
        model_name = "microsoft/Phi-3.5-mini-instruct"
        
        # Check if CUDA is available
        device = "cuda" if torch.cuda.is_available() else "cpu"
        print(f"📱 Using device: {device}")
        
        # Load tokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(
            model_name,
            trust_remote_code=True,
            padding_side="left"
        )
        
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
        
        # Load model with optimizations
        self.model = AutoModelForCausalLM.from_pretrained(
            model_name,
            torch_dtype=torch.float16 if device == "cuda" else torch.float32,
            device_map="auto" if device == "cuda" else None,
            trust_remote_code=True,
            low_cpu_mem_usage=True
        )
        
        if device == "cpu":
            self.model = self.model.to(device)
        
        self.model.eval()
        print("✅ Phi-3.5-Mini loaded successfully!")

    def _setup_patterns(self):
        """Setup regex patterns for quick detection"""
        self.patterns = {
            'credit_card': [
                re.compile(r'\b4[0-9]{12}(?:[0-9]{3})?\b'),         # Visa
                re.compile(r'\b5[1-5][0-9]{14}\b'),                 # Mastercard
                re.compile(r'\b3[47][0-9]{13}\b'),                  # American Express
                re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),         # Generic format
            ],
            'jwt_token': re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'),
            'api_key': [
                re.compile(r'sk-[A-Za-z0-9]{48}'),                  # OpenAI API key
                re.compile(r'AKIA[0-9A-Z]{16}'),                    # AWS Access Key
                re.compile(r'ghp_[A-Za-z0-9]{36}'),                 # GitHub Personal Token
                re.compile(r'AIza[0-9A-Za-z-_]{35}'),               # Google API Key
                re.compile(r'\b[A-Za-z0-9]{32,64}\b'),              # Generic API keys
            ],
            'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            'phone': re.compile(r'\b(?:\+1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'password': re.compile(r'(?:password|pwd|pass|secret)[\s:=]+[^\s]{6,}', re.IGNORECASE),
            'private_key': re.compile(r'-----BEGIN[A-Z\s]+PRIVATE KEY-----'),
        }

    def quick_regex_scan(self, text: str) -> List[Dict]:
        """Fast regex-based detection"""
        findings = []
        
        for category, pattern_list in self.patterns.items():
            patterns = pattern_list if isinstance(pattern_list, list) else [pattern_list]
            
            for pattern in patterns:
                matches = pattern.finditer(text)
                for match in matches:
                    findings.append({
                        'type': category,
                        'text': match.group(),
                        'start': match.start(),
                        'end': match.end(),
                        'confidence': 0.95,
                        'method': 'regex'
                    })
        
        return findings

    def analyze_with_phi(self, text: str) -> Dict:
        """Use Phi-3.5-Mini to analyze text for sensitive information"""
        
        # Create a focused prompt for Phi-3.5
        system_message = """You are a security assistant that detects sensitive information in text. 
Analyze the text for: credit cards, API keys, JWT tokens, SSN, passwords, private keys, personal info.
Respond with JSON format only."""

        user_message = f"""Analyze this text for sensitive information:

Text: "{text}"

Respond with JSON only:
{{
    "has_sensitive_data": true/false,
    "confidence": 0.0-1.0,
    "types_found": ["credit_card", "api_key", "jwt_token", "ssn", "password", "email", "phone"]
}}"""

        messages = [
            {"role": "system", "content": system_message},
            {"role": "user", "content": user_message}
        ]

        try:
            # Apply chat template
            prompt = self.tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True
            )

            # Tokenize with proper attention mask
            inputs = self.tokenizer(
                prompt,
                return_tensors="pt",
                max_length=1024,
                truncation=True,
                padding=True
            ).to(self.model.device)

            # Generate response
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=150,
                    temperature=0.1,
                    do_sample=True,
                    pad_token_id=self.tokenizer.eos_token_id,
                    eos_token_id=self.tokenizer.eos_token_id,
                    repetition_penalty=1.1
                )

            # Decode response
            response = self.tokenizer.decode(
                outputs[0][inputs['input_ids'].shape[1]:],
                skip_special_tokens=True
            )

            return self._parse_phi_response(response)

        except Exception as e:
            print(f"⚠️  Phi analysis failed: {e}")
            return {"has_sensitive_data": False, "confidence": 0.0, "types_found": []}

    def _parse_phi_response(self, response: str) -> Dict:
        """Parse Phi-3.5-Mini JSON response"""
        try:
            # Find JSON in response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            
            if json_start != -1 and json_end > json_start:
                json_str = response[json_start:json_end]
                parsed = json.loads(json_str)
                
                # Validate the response structure
                if isinstance(parsed, dict) and 'has_sensitive_data' in parsed:
                    return parsed
                    
        except json.JSONDecodeError as e:
            print(f"JSON parse error: {e}")
        except Exception as e:
            print(f"Response parse error: {e}")
        
        return {"has_sensitive_data": False, "confidence": 0.0, "types_found": []}

    def redact_sensitive_info(self, text: str, regex_findings: List[Dict], ai_types: List[str]) -> str:
        """Redact sensitive information with appropriate placeholders"""
        redacted_text = text
        
        # Redaction mappings
        redaction_map = {
            'credit_card': '[REDACTED-CREDIT-CARD]',
            'jwt_token': '[REDACTED-JWT-TOKEN]',
            'api_key': '[REDACTED-API-KEY]',
            'ssn': '[REDACTED-SSN]',
            'phone': '[REDACTED-PHONE]',
            'email': '[REDACTED-EMAIL]',
            'password': '[REDACTED-PASSWORD]',
            'private_key': '[REDACTED-PRIVATE-KEY]',
        }

        # Sort findings by position (reverse order to maintain indices)
        sorted_findings = sorted(regex_findings, key=lambda x: x['start'], reverse=True)

        # Apply regex-based redactions
        for finding in sorted_findings:
            if finding['confidence'] > 0.8:
                start, end = finding['start'], finding['end']
                redaction = redaction_map.get(finding['type'], '[REDACTED]')
                redacted_text = redacted_text[:start] + redaction + redacted_text[end:]

        # If AI found additional types not caught by regex, do a more aggressive redaction
        if ai_types and len(redacted_text) == len(text):  # No regex redactions were made
            for ai_type in ai_types:
                if ai_type in redaction_map:
                    # For AI-detected items without specific positions, 
                    # we could implement more sophisticated redaction
                    pass

        return redacted_text

    def process_clipboard_content(self, content: str) -> str:
        """Main processing pipeline"""
        if len(content.strip()) < 3:
            return content

        print(f"🔍 Analyzing: {content[:60]}{'...' if len(content) > 60 else ''}")

        # Step 1: Quick regex scan
        regex_findings = self.quick_regex_scan(content)
        
        # Step 2: Decide whether to use AI
        # Use AI if: regex found something, or content is short and potentially sensitive
        use_ai = bool(regex_findings) or (len(content.strip()) < 300 and any(
            keyword in content.lower() for keyword in 
            ['key', 'token', 'password', 'secret', 'api', 'jwt', 'bearer', 'auth']
        ))

        ai_result = {"has_sensitive_data": False, "types_found": []}
        
        if use_ai:
            print("🤖 Verifying with Phi-3.5-Mini...")
            ai_result = self.analyze_with_phi(content)

        # Step 3: Make decision
        should_redact = bool(regex_findings) or (
            ai_result.get('has_sensitive_data', False) and 
            ai_result.get('confidence', 0) > 0.7
        )

        if should_redact:
            types_found = list(set([f['type'] for f in regex_findings] + ai_result.get('types_found', [])))
            print(f"⚠️  Sensitive data detected: {', '.join(types_found)}")
            
            redacted_content = self.redact_sensitive_info(
                content, 
                regex_findings, 
                ai_result.get('types_found', [])
            )
            
            if redacted_content != content:
                print("✅ Content redacted successfully!")
                return redacted_content

        print("✅ Content is safe")
        return content

    def monitor_clipboard(self):
        """Background clipboard monitoring"""
        print("🔒 Clipboard monitoring started!")
        print("📋 Copy some text to test the security...")
        print("🛑 Press Ctrl+C to stop\n")

        while self.monitoring:
            try:
                current_content = pyperclip.paste()
                current_hash = hashlib.md5(current_content.encode()).hexdigest()

                if current_hash != self.last_hash and current_content.strip():
                    self.last_hash = current_hash

                    # Process the content
                    safe_content = self.process_clipboard_content(current_content)

                    # Update clipboard if content was modified
                    if safe_content != current_content:
                        pyperclip.copy(safe_content)
                        print("🛡️  Clipboard automatically secured!\n")

                time.sleep(1)  # Check every second

            except Exception as e:
                print(f"❌ Monitor error: {e}")
                time.sleep(2)

    def start_monitoring(self):
        """Start clipboard monitoring in background thread"""
        if not self.monitoring:
            self.monitoring = True
            monitor_thread = threading.Thread(target=self.monitor_clipboard, daemon=True)
            monitor_thread.start()
            return monitor_thread
        return None

    def stop_monitoring(self):
        """Stop clipboard monitoring"""
        self.monitoring = False
        print("🛑 Clipboard monitoring stopped")

    def test_detection(self):
        """Test the detection system with sample data"""
        print("\n🧪 Testing detection system:")
        print("-" * 40)
        
        test_cases = [
            "My credit card number is 4532-1234-5678-9012",
            "API key: sk_1234567890abcdefghijklmnopqrstuvwxyz123456",
            "JWT token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature",
            "Contact me at john.doe@example.com or 555-123-4567",
            "My SSN is 123-45-6789",
            "This is just normal text with no sensitive information",
            "Bearer eyJhbGciOiJIUzI1NiJ9.dGVzdA.secret",
        ]

        for i, test in enumerate(test_cases, 1):
            print(f"\nTest {i}:")
            result = self.process_clipboard_content(test)
            
            if result != test:
                print(f"  Input:  '{test}'")
                print(f"  Output: '{result}'")
                print(f"  Status: ❌ REDACTED")
            else:
                print(f"  Input:  '{test}'")
                print(f"  Status: ✅ SAFE")


def main():
    """Main function"""
    print("🎯 Phi-3.5-Mini Clipboard Security for Qualcomm Edge AI Hackathon")
    print("🔐 Protecting your sensitive data in real-time")
    print("=" * 70)

    try:
        # Initialize security system
        security = PhiClipboardSecurity()

        # Run tests first
        security.test_detection()

        print("\n" + "="*50)
        print("🚀 Starting real-time clipboard monitoring...")
        
        # Start monitoring
        security.start_monitoring()

        # Keep the main thread alive
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n\n🛑 Stopping clipboard security...")
        if 'security' in locals():
            security.stop_monitoring()
        print("👋 Thank you for using Phi-3.5-Mini Clipboard Security!")
        
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        print("🔧 Please check your setup and try again.")


if __name__ == "__main__":
    main()