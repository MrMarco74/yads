#!/usr/bin/env python3
"""
YADS Release Automation Tool

Automates the complete release process including version bumping,
changelog generation, translation, packaging, and deployment.

Usage:
    ./tools/release.py release --bump patch
    ./tools/release.py release --bump minor --dry-run
    ./tools/release.py upload --version 1.13.4
    ./tools/release.py init-config
"""

import sys
import os
import subprocess
import argparse
from pathlib import Path
from typing import Optional

# Add release_lib to path
sys.path.insert(0, str(Path(__file__).parent))

from release_lib.version import SemanticVersion, extract_version_from_file
from release_lib.config import ReleaseConfig
from release_lib.changelog import ChangelogManager
from release_lib.translator import ChangelogTranslator
from release_lib.updater import FileUpdater
from release_lib.uploader import ReleaseUploader


class ReleaseOrchestrator:
    """Main orchestrator for release process"""

    def __init__(self, project_root: str, config_path: Optional[str] = None):
        """
        Initialize orchestrator.

        Args:
            project_root: Root directory of YADS project
            config_path: Optional path to config file
        """
        self.project_root = Path(project_root)
        self.config_path = config_path
        self.config = None

        # Components (initialized when needed)
        self.changelog_manager = ChangelogManager()
        self.translator = None
        self.file_updater = FileUpdater(str(self.project_root))
        self.uploader = None

    def load_config(self) -> None:
        """Load and validate configuration"""
        try:
            self.config = ReleaseConfig(self.config_path)
            self.config.validate()

            # Initialize translator
            translation_config = self.config.get('translation', {})
            self.translator = ChangelogTranslator(
                api_key=translation_config.get('api_key'),
                service=translation_config.get('service', 'deepl')
            )

            # Initialize uploader
            self.uploader = ReleaseUploader(
                self.config.config,
                str(self.project_root)
            )

        except FileNotFoundError as e:
            print(f"\n❌ {e}\n")
            sys.exit(1)
        except ValueError as e:
            print(f"\n❌ Configuration error:\n{e}\n")
            sys.exit(1)

    def pre_flight_checks(self) -> bool:
        """
        Run pre-flight checks before release.

        Returns:
            True if all checks pass
        """
        print("\n🔍 Running pre-flight checks...\n")

        checks_passed = True

        # Check if in git repository
        try:
            subprocess.run(
                ['git', 'rev-parse', '--git-dir'],
                cwd=self.project_root,
                check=True,
                capture_output=True
            )
            print("  ✅ Git repository detected")
        except subprocess.CalledProcessError:
            print("  ⚠️  Not in a git repository")

        # Check for uncommitted changes
        try:
            result = subprocess.run(
                ['git', 'status', '--porcelain'],
                cwd=self.project_root,
                check=True,
                capture_output=True,
                text=True
            )

            if result.stdout.strip():
                print("  ⚠️  Uncommitted changes detected:")
                for line in result.stdout.strip().split('\n')[:5]:
                    print(f"      {line}")
                print("\n  Note: These will be included in the release commit")
            else:
                print("  ✅ Working directory clean")

        except subprocess.CalledProcessError:
            pass

        # Check config file exists
        config_file = self.project_root / "yads" / "config.py"
        if config_file.exists():
            print(f"  ✅ Config file found: {config_file}")
        else:
            print(f"  ❌ Config file not found: {config_file}")
            checks_passed = False

        # Check package script exists
        package_script = self.project_root / "tools" / "package_release.sh"
        if package_script.exists():
            print(f"  ✅ Package script found: {package_script}")
        else:
            print(f"  ❌ Package script not found: {package_script}")
            checks_passed = False

        print()
        return checks_passed

    def execute_release(
        self,
        bump_type: str,
        dry_run: bool = False,
        skip_upload: bool = False,
        skip_commit: bool = False,
        use_editor: bool = False
    ) -> bool:
        """
        Execute full release process.

        Args:
            bump_type: Version bump type ('major', 'minor', 'patch')
            dry_run: If True, preview changes without executing
            skip_upload: If True, skip upload step
            skip_commit: If True, skip git commit
            use_editor: If True, use editor for changelog

        Returns:
            True if successful
        """
        try:
            # Pre-flight checks
            if not self.pre_flight_checks():
                print("❌ Pre-flight checks failed!")
                return False

            # Load configuration (unless dry run and skipping upload)
            if not (dry_run and skip_upload):
                self.load_config()

            # Step 1: Version bump
            print("="*60)
            print("  STEP 1: Version Bump")
            print("="*60)

            config_file = self.project_root / "yads" / "config.py"
            current_version = extract_version_from_file(str(config_file))
            new_version_str = current_version.bump(bump_type)
            new_version = SemanticVersion(new_version_str)

            print(f"\nCurrent version: {current_version}")
            print(f"New version:     {new_version}")
            print(f"Bump type:       {bump_type.upper()}\n")

            if not dry_run:
                confirm = input("Proceed with this version bump? [y/N]: ").strip().lower()
                if confirm != 'y':
                    print("Aborted by user.")
                    return False

            # Step 2: Changelog collection
            print("\n" + "="*60)
            print("  STEP 2: Changelog Collection")
            print("="*60)

            if use_editor:
                changelog_en = self.changelog_manager.collect_from_editor(new_version_str)
            else:
                changelog_en = self.changelog_manager.collect_interactive(new_version_str)

            # Preview English changelog
            self.changelog_manager.preview_changelog(changelog_en)

            if not dry_run:
                confirm = input("\nProceed with this changelog? [y/N]: ").strip().lower()
                if confirm != 'y':
                    print("Aborted by user.")
                    return False

            # Step 3: Translation
            print("\n" + "="*60)
            print("  STEP 3: Translation (EN → DE)")
            print("="*60 + "\n")

            if dry_run:
                print("⏭️  Skipping translation in dry-run mode")
                changelog_de = changelog_en  # Use English as placeholder
            else:
                changelog_de = self.translator.translate_changelog(changelog_en)

                # Preview German changelog
                print("\n--- German Translation Preview ---\n")
                self.changelog_manager.preview_changelog(changelog_de)

            # Step 4: Generate code
            print("\n" + "="*60)
            print("  STEP 4: Code Generation")
            print("="*60 + "\n")

            python_code_en = self.changelog_manager.generate_python_code(changelog_en, 'en')
            notification_code = self.changelog_manager.generate_notification_code(changelog_en, 'en')
            html_en = self.changelog_manager.generate_html(changelog_en)
            html_de = self.changelog_manager.generate_html(changelog_de)

            if dry_run:
                print("--- Python Code (seeding.py) ---")
                print(python_code_en[:500] + "..." if len(python_code_en) > 500 else python_code_en)
                print("\n--- HTML (changes.html EN) ---")
                print(html_en[:300] + "..." if len(html_en) > 300 else html_en)

            # Step 5: File updates
            print("\n" + "="*60)
            print("  STEP 5: File Updates")
            print("="*60 + "\n")

            results = self.file_updater.update_all_files(
                version=new_version_str,
                changelog_code=python_code_en,
                changelog_html_en=html_en,
                changelog_html_de=html_de,
                notification_code=notification_code,
                dry_run=dry_run
            )

            # Display results
            for result in results:
                status = "✅" if result['changed'] else "⏭️ "
                print(f"  {status} {result['file']} ({result['matches']} matches)")

            if dry_run:
                print("\n✅ Dry run completed! Use --no-dry-run to execute.\n")
                return True

            # Step 6: Packaging
            print("\n" + "="*60)
            print("  STEP 6: Packaging")
            print("="*60 + "\n")

            package_script = self.project_root / "tools" / "package_release.sh"
            print(f"Executing: {package_script}\n")

            result = subprocess.run(
                [str(package_script)],
                cwd=self.project_root,
                check=False
            )

            if result.returncode != 0:
                print("\n❌ Packaging failed!")
                print("Rolling back file changes...")
                self.file_updater.rollback()
                return False

            print("\n✅ Packaging completed successfully")

            # Step 7: Upload
            if not skip_upload:
                print("\n" + "="*60)
                print("  STEP 7: Upload")
                print("="*60)

                try:
                    self.uploader.upload_release(new_version_str, dry_run=False)
                except Exception as e:
                    print(f"\n⚠️  Upload failed: {e}")
                    print(f"\nYou can retry later with:")
                    print(f"  ./tools/release.py upload --version {new_version_str}\n")
            else:
                print("\n⏭️  Skipping upload (--no-upload)")

            # Step 8: Git operations
            if not skip_commit:
                print("\n" + "="*60)
                print("  STEP 8: Git Commit & Tag")
                print("="*60 + "\n")

                self._git_commit_and_tag(new_version_str, changelog_en['title'])
            else:
                print("\n⏭️  Skipping git commit (--no-commit)")

            # Cleanup backups
            self.file_updater.cleanup_backups()

            print("\n" + "="*60)
            print("  🎉 RELEASE COMPLETED SUCCESSFULLY!")
            print("="*60)
            print(f"\nVersion {new_version_str} has been released.\n")

            return True

        except KeyboardInterrupt:
            print("\n\n⚠️  Release interrupted by user")
            if not dry_run:
                print("Rolling back changes...")
                self.file_updater.rollback()
            return False

        except Exception as e:
            print(f"\n❌ Release failed: {e}")
            if not dry_run:
                print("Rolling back changes...")
                self.file_updater.rollback()
            raise

    def retry_upload(self, version: str) -> bool:
        """
        Retry upload for an existing release.

        Args:
            version: Version string to upload

        Returns:
            True if successful
        """
        print(f"\n📤 Retrying upload for version {version}...\n")

        self.load_config()

        try:
            return self.uploader.upload_release(version, dry_run=False)
        except Exception as e:
            print(f"\n❌ Upload failed: {e}\n")
            return False

    def _git_commit_and_tag(self, version: str, title: str) -> None:
        """
        Create git commit and tag.

        Args:
            version: Version string
            title: Release title
        """
        commit_message = f"Release v{version}: {title}"

        # Stage all changes
        subprocess.run(
            ['git', 'add', '-A'],
            cwd=self.project_root,
            check=True
        )

        # Commit
        subprocess.run(
            ['git', 'commit', '-m', commit_message],
            cwd=self.project_root,
            check=True
        )

        print(f"  ✅ Committed: {commit_message}")

        # Create tag
        tag_name = f"v{version}"
        subprocess.run(
            ['git', 'tag', '-a', tag_name, '-m', f"Release {version}"],
            cwd=self.project_root,
            check=True
        )

        print(f"  ✅ Tagged: {tag_name}")

        # Ask about push
        push = input("\nPush to remote? [y/N]: ").strip().lower()
        if push == 'y':
            subprocess.run(
                ['git', 'push'],
                cwd=self.project_root,
                check=True
            )
            subprocess.run(
                ['git', 'push', '--tags'],
                cwd=self.project_root,
                check=True
            )
            print("  ✅ Pushed to remote")
        else:
            print("  ⏭️  Skipped push (run 'git push && git push --tags' manually)")


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='YADS Release Automation Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full release with patch bump
  ./tools/release.py release --bump patch

  # Preview major version release
  ./tools/release.py release --bump major --dry-run

  # Release without upload
  ./tools/release.py release --bump minor --no-upload

  # Retry upload for existing release
  ./tools/release.py upload --version 1.13.4

  # Initialize configuration
  ./tools/release.py init-config
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # Release command
    release_parser = subparsers.add_parser('release', help='Execute full release process')
    release_parser.add_argument(
        '--bump',
        choices=['major', 'minor', 'patch'],
        required=True,
        help='Version bump type'
    )
    release_parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Preview changes without executing'
    )
    release_parser.add_argument(
        '--no-upload',
        action='store_true',
        help='Skip upload step'
    )
    release_parser.add_argument(
        '--no-commit',
        action='store_true',
        help='Skip git commit'
    )
    release_parser.add_argument(
        '--editor',
        action='store_true',
        help='Use editor for changelog (instead of interactive)'
    )
    release_parser.add_argument(
        '--config',
        help='Path to config file (default: ~/.yads/release.yaml)'
    )

    # Upload command
    upload_parser = subparsers.add_parser('upload', help='Retry upload for existing release')
    upload_parser.add_argument(
        '--version',
        required=True,
        help='Version to upload (e.g., 1.13.4)'
    )
    upload_parser.add_argument(
        '--config',
        help='Path to config file'
    )

    # Init-config command
    init_parser = subparsers.add_parser('init-config', help='Create configuration template')
    init_parser.add_argument(
        '--output',
        help='Output path (default: ~/.yads/release.yaml)'
    )

    # Version command
    version_parser = subparsers.add_parser('version', help='Show current version')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Determine project root
    script_dir = Path(__file__).parent
    project_root = script_dir.parent

    # Execute command
    if args.command == 'init-config':
        output_path = args.output if hasattr(args, 'output') else None
        config_path = ReleaseConfig.create_template(output_path)
        print(f"\n✅ Configuration template created: {config_path}")
        print("\nEdit this file to add your credentials and settings.")
        print("Remember to set environment variables for sensitive data:\n")
        print("  export DEEPL_API_KEY='your-api-key'")
        print("  export YADS_FTP_PASSWORD='your-ftp-password'\n")
        sys.exit(0)

    elif args.command == 'version':
        config_file = project_root / "yads" / "config.py"
        current_version = extract_version_from_file(str(config_file))
        print(f"\nCurrent version: {current_version}\n")
        sys.exit(0)

    elif args.command == 'release':
        orchestrator = ReleaseOrchestrator(
            str(project_root),
            args.config if hasattr(args, 'config') else None
        )

        success = orchestrator.execute_release(
            bump_type=args.bump,
            dry_run=args.dry_run,
            skip_upload=args.no_upload,
            skip_commit=args.no_commit,
            use_editor=args.editor
        )

        sys.exit(0 if success else 1)

    elif args.command == 'upload':
        orchestrator = ReleaseOrchestrator(
            str(project_root),
            args.config if hasattr(args, 'config') else None
        )

        success = orchestrator.retry_upload(args.version)
        sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
