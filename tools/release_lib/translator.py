"""
Translation System

Handles automated translation of changelog entries using Google Gemini (AI Studio) or Vertex AI (GCP).
"""

import json
import os
from typing import Dict, List, Optional


class ChangelogTranslator:
    """Translate changelog entries EN → DE using Gemini or Vertex AI"""

    def __init__(self, api_key: Optional[str] = None, service: str = 'gemini', project_id: Optional[str] = None, location: Optional[str] = 'us-central1', model_name: str = 'gemini-2.0-flash'):
        """
        Initialize translator.

        Args:
            api_key: API key for Gemini (AI Studio)
            service: Translation service ('gemini', 'vertexai', or 'manual')
            project_id: GCP project ID (for Vertex AI)
            location: GCP location (for Vertex AI)
            model_name: Name of the Gemini model to use
        """
        self.api_key = api_key
        self.service = service
        self.project_id = project_id
        self.location = location
        self.model_name = model_name
        self.model = None

        if service == 'gemini':
            if api_key:
                self._initialize_gemini(api_key, model_name)
            else:
                self.service = 'manual'
        elif service == 'vertexai':
            if project_id:
                self._initialize_vertexai(project_id, location, model_name)
            else:
                self.service = 'manual'

    def _initialize_gemini(self, api_key: str, model_name: str):
        """Initialize Google AI Studio Gemini"""
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel(model_name)
        except ImportError:
            print("⚠️  Warning: google-generativeai package not installed.")
            self.service = 'manual'
        except Exception as e:
            print(f"⚠️  Warning: Gemini initialization failed: {e}")
            self.service = 'manual'

    def _initialize_vertexai(self, project_id: Optional[str], location: str, model_name: str):
        """Initialize Google Cloud Vertex AI"""
        try:
            import vertexai
            from vertexai.generative_models import GenerativeModel
            
            vertexai.init(project=project_id, location=location)
            self.model = GenerativeModel(model_name)
            print(f"☁️  Vertex AI initialized (Project: {project_id or 'default'}, Location: {location}, Model: {model_name})")
        except ImportError:
            print("⚠️  Warning: google-cloud-aiplatform package not installed. Install with: pip install google-cloud-aiplatform")
            self.service = 'manual'
        except Exception as e:
            print(f"⚠️  Warning: Vertex AI initialization failed: {e}")
            print("Ensure you have valid GCP credentials (ADC) or are running on a GCP resource.")
            self.service = 'manual'

    def translate_changelog(self, changelog_data: Dict, interactive: bool = True) -> Dict:
        """
        Translate changelog data from English to German.

        Args:
            changelog_data: Changelog data with English text
            interactive: Whether to allow manual interaction/prompts

        Returns:
            Changelog data with German text
        """
        if self.service in ['gemini', 'vertexai']:
            if self.model:
                return self._translate_automated(changelog_data, interactive=interactive)
            else:
                print(f"⚠️  {self.service.capitalize()} model not initialized. Falling back to manual translation.")
                return self._translate_manual(changelog_data, interactive=interactive)
        elif self.service == 'manual':
            return self._translate_manual(changelog_data, interactive=interactive)
        else:
            raise ValueError(f"Unsupported translation service: {self.service}")

    # Section name translations (English → German)
    SECTION_TRANSLATIONS = {
        '🚀 New Features': '🚀 Neue Funktionen',
        '🚀 Neue Funktionen': '🚀 Neue Funktionen',
        '⚡ Improvements': '⚡ Verbesserungen',
        '⚡ Verbesserungen': '⚡ Verbesserungen',
        '🐛 Bug Fixes': '🐛 Fehlerbehebungen',
        '🐛 Fehlerbehebungen': '🐛 Fehlerbehebungen',
        '🔒 Security': '🔒 Sicherheit',
        '🔒 Sicherheit': '🔒 Sicherheit',
        '📈 Performance': '📈 Performance',
        '📚 Documentation': '📚 Dokumentation',
        '📚 Dokumentation': '📚 Dokumentation',
        '💥 Breaking Changes': '💥 Breaking Changes',
        '🔧 Technical Improvements': '🔧 Technische Verbesserungen',
        '🔧 Technische Verbesserungen': '🔧 Technische Verbesserungen',
    }

    def _translate_section_name(self, name: str) -> str:
        """Translate section name to German using predefined mappings."""
        return self.SECTION_TRANSLATIONS.get(name, name)

    def _translate_automated(self, changelog_data: Dict, interactive: bool = True) -> Dict:
        """
        Translate using automated Gemini/Vertex AI API.

        Args:
            changelog_data: English changelog data

        Returns:
            German changelog data
        """
        try:
            source_name = "Vertex AI" if self.service == 'vertexai' else "Gemini"
            print(f"🤖 {source_name} is translating...")

            # Prepare the prompt
            prompt = f"""
            Translate the following changelog JSON from English to German.
            Keep the JSON structure exactly as it is.
            Translate the 'title', the 'name' fields in sections, and all strings in the 'items' lists.
            Keep the emojis in the section names.
            Ensure the tone is professional but concise.

            Standard section name translations:
            - "🚀 New Features" → "🚀 Neue Funktionen"
            - "⚡ Improvements" → "⚡ Verbesserungen"
            - "🐛 Bug Fixes" → "🐛 Fehlerbehebungen"
            - "🔒 Security" → "🔒 Sicherheit"
            - "📚 Documentation" → "📚 Dokumentation"
            - "🔧 Technical Improvements" → "🔧 Technische Verbesserungen"

            JSON:
            {json.dumps(changelog_data, indent=2)}
            """

            response = self.model.generate_content(prompt)

            # Extract JSON from response (handling potential markdown formatting)
            text = response.text.strip()
            if text.startswith("```json"):
                text = text[7:]
            if text.endswith("```"):
                text = text[:-3]

            translated_data = json.loads(text)

            if 'sections' not in translated_data or 'title' not in translated_data:
                raise ValueError("AI returned invalid JSON structure")

            # Ensure section names are consistently translated using our mapping
            for section in translated_data.get('sections', []):
                section['name'] = self._translate_section_name(section.get('name', ''))

            return translated_data

        except Exception as e:
            print(f"⚠️  Automated translation failed: {e}")
            print("Falling back to manual translation...")
            return self._translate_manual(changelog_data, interactive=interactive)

    def _translate_manual(self, changelog_data: Dict, interactive: bool = True) -> Dict:
        """
        Collect manual translations interactively.

        Args:
            changelog_data: English changelog data
            interactive: Whether to allow manual interaction/prompts

        Returns:
            German changelog data
        """
        if not interactive:
            print("⏭️  Manual translation skipped (non-interactive mode).")
            # Returns a copy with section names translated
            return {
                'version': changelog_data['version'],
                'title': changelog_data['title'],
                'sections': [
                    {
                        'key': s.get('key', ''),
                        'name': self._translate_section_name(s['name']),
                        'items': list(s['items'])
                    }
                    for s in changelog_data['sections']
                ]
            }

        print("\n--- Manual German Translation ---\n")

        # Translate title
        print(f"EN: {changelog_data['title']}")
        title_de = input("DE: ").strip()
        if not title_de:
            title_de = changelog_data['title']

        # Translate sections
        sections_de = []
        for section in changelog_data['sections']:
            # Auto-translate section name
            section_name_de = self._translate_section_name(section['name'])
            print(f"\n{section['name']} → {section_name_de}")

            items_de = []
            for item in section['items']:
                print(f"  EN: {item}")
                item_de = input(f"  DE: ").strip()
                items_de.append(item_de or item)

            sections_de.append({
                'key': section.get('key', ''),
                'name': section_name_de,
                'items': items_de
            })

        return {
            'version': changelog_data['version'],
            'title': title_de,
            'sections': sections_de
        }

    def test_connection(self) -> bool:
        """
        Test if translation service is available.

        Returns:
            True if service is available
        """
        if self.model:
            try:
                response = self.model.generate_content("Say 'OK'")
                return "OK" in response.text
            except Exception as e:
                print(f"Connection test failed: {e}")
                return False
        elif self.service == 'manual':
            return True
        else:
            return False
