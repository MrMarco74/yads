"""
Translation System

Handles automated translation of changelog entries using DeepL API.
"""

from typing import Dict, List, Optional


class ChangelogTranslator:
    """Translate changelog entries EN → DE"""

    def __init__(self, api_key: Optional[str] = None, service: str = 'deepl'):
        """
        Initialize translator.

        Args:
            api_key: API key for translation service
            service: Translation service ('deepl', 'google', or 'manual')
        """
        self.api_key = api_key
        self.service = service
        self.translator = None

        if service == 'deepl' and api_key:
            try:
                import deepl
                self.translator = deepl.Translator(api_key)
            except ImportError:
                print("⚠️  Warning: deepl package not installed. Install with: pip install deepl")
                self.service = 'manual'
            except Exception as e:
                print(f"⚠️  Warning: DeepL initialization failed: {e}")
                self.service = 'manual'

    def translate_changelog(self, changelog_data: Dict) -> Dict:
        """
        Translate changelog data from English to German.

        Args:
            changelog_data: Changelog data with English text

        Returns:
            Changelog data with German text
        """
        if self.service == 'deepl' and self.translator:
            return self._translate_with_deepl(changelog_data)
        elif self.service == 'manual':
            return self._translate_manual(changelog_data)
        else:
            raise ValueError(f"Unsupported translation service: {self.service}")

    def _translate_with_deepl(self, changelog_data: Dict) -> Dict:
        """
        Translate using DeepL API.

        Args:
            changelog_data: English changelog data

        Returns:
            German changelog data
        """
        try:
            # Translate title
            title_result = self.translator.translate_text(
                changelog_data['title'],
                source_lang="EN",
                target_lang="DE"
            )
            title_de = title_result.text

            # Translate sections
            sections_de = []
            for section in changelog_data['sections']:
                items_de = []

                for item in section['items']:
                    try:
                        result = self.translator.translate_text(
                            item,
                            source_lang="EN",
                            target_lang="DE"
                        )
                        items_de.append(result.text)
                    except Exception as e:
                        print(f"⚠️  Translation failed for item: {item}")
                        print(f"   Error: {e}")
                        print(f"   Using manual fallback...")
                        manual_translation = input(f"   DE translation for '{item}': ").strip()
                        items_de.append(manual_translation or item)

                sections_de.append({
                    'key': section.get('key', ''),
                    'name': section['name'],  # Keep emoji unchanged
                    'items': items_de
                })

            return {
                'version': changelog_data['version'],
                'title': title_de,
                'sections': sections_de
            }

        except Exception as e:
            print(f"⚠️  DeepL API error: {e}")
            print("Falling back to manual translation...")
            return self._translate_manual(changelog_data)

    def _translate_manual(self, changelog_data: Dict) -> Dict:
        """
        Collect manual translations interactively.

        Args:
            changelog_data: English changelog data

        Returns:
            German changelog data
        """
        print("\n--- Manual German Translation ---\n")

        # Translate title
        print(f"EN: {changelog_data['title']}")
        title_de = input("DE: ").strip()
        if not title_de:
            title_de = changelog_data['title']

        # Translate sections
        sections_de = []
        for section in changelog_data['sections']:
            print(f"\n{section['name']}")

            items_de = []
            for item in section['items']:
                print(f"  EN: {item}")
                item_de = input(f"  DE: ").strip()
                items_de.append(item_de or item)

            sections_de.append({
                'key': section.get('key', ''),
                'name': section['name'],
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
        if self.service == 'deepl' and self.translator:
            try:
                # Try a simple translation
                result = self.translator.translate_text(
                    "Hello",
                    source_lang="EN",
                    target_lang="DE"
                )
                return result.text == "Hallo"
            except Exception as e:
                print(f"DeepL connection test failed: {e}")
                return False
        elif self.service == 'manual':
            return True
        else:
            return False
