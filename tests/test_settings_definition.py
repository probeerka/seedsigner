import os
from unittest.mock import Mock

from base import BaseTest
from seedsigner.models.settings_definition import SettingsConstants, SettingsDefinition


class TestSettingsDefinition(BaseTest):
    @classmethod
    def setup_class(cls):
        super().setup_class()


    def test__get_detected_languages(self):
        """ Should auto-detect onboard languages based on the supported locales list """
        detected_languages = [lang_tuple[0] for lang_tuple in SettingsConstants.get_detected_languages()]

        # Find an unused language code; avoiding hard coding a language code to keep
        # this test future proof.
        absent_language_code = None
        for language_code in SettingsConstants.ALL_LOCALES.keys():
            if language_code not in detected_languages:
                absent_language_code = language_code
                break
        
        # Should only fail if we've absolutely crushed the global translations!!!
        assert absent_language_code is not None

        root = os.path.join(os.getcwd(), "src", "seedsigner", "resources", "seedsigner-translations", "l10n")

        # We're going to mock the `root` results to include the absent language code's .mo file
        mocked_results = [(os.path.join(root, "en", "LC_MESSAGES"), [], ["messages.po", "messages.mo"])]
        mocked_results.append((os.path.join(root, absent_language_code, "LC_MESSAGES"), [], ["messages.po", "messages.mo"]))
        os.walk = Mock(return_value=mocked_results)

        # Recheck w/our mocked dir listing:
        detected_languages = [lang_tuple[0] for lang_tuple in SettingsConstants.get_detected_languages()]
        assert absent_language_code in detected_languages

    def test_default_seed_word_lengths(self):
        defaults = SettingsDefinition.get_defaults()
        assert defaults[SettingsConstants.SETTING__SEED_WORD_LENGTHS] == [12, 24]


    def test_tapsigner_backup_default_disabled(self):
        defaults = SettingsDefinition.get_defaults()
        assert defaults[SettingsConstants.SETTING__TAPSIGNER_BACKUP] == SettingsConstants.OPTION__DISABLED

    def test_alt_networks_default_disabled(self):
        """ALT_NETWORKS should be disabled by default (empty selection)"""
        defaults = SettingsDefinition.get_defaults()
        alt_networks = defaults[SettingsConstants.SETTING__ALT_NETWORKS]
        assert SettingsConstants.ALT_NETWORK__ERC20 not in alt_networks
        assert SettingsConstants.ALT_NETWORK__TRC20 not in alt_networks

    def test_alt_networks_constants_exist(self):
        """ALT_NETWORK constants should be defined"""
        assert hasattr(SettingsConstants, "SETTING__ALT_NETWORKS")
        assert hasattr(SettingsConstants, "ALT_NETWORK__ERC20")
        assert hasattr(SettingsConstants, "ALT_NETWORK__TRC20")
        assert SettingsConstants.ALT_NETWORK__ERC20 == "erc20"
        assert SettingsConstants.ALT_NETWORK__TRC20 == "trc20"

    def test_alt_networks_setting_entry_exists(self):
        """ALT_NETWORKS should have a valid SettingsEntry"""
        entry = SettingsDefinition.get_settings_entry(SettingsConstants.SETTING__ALT_NETWORKS)
        assert entry is not None
        assert entry.visibility == SettingsConstants.VISIBILITY__ADVANCED
        # selection_options should include ERC20 and TRC20
        option_values = [o[0] for o in entry.selection_options]
        assert SettingsConstants.ALT_NETWORK__ERC20 in option_values
        assert SettingsConstants.ALT_NETWORK__TRC20 in option_values

