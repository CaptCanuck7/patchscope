"""Tests for the Complexity Assessor agent tools and branching logic."""

import pytest
from unittest.mock import patch, MagicMock

from patchscope.agents.complexity_assessor import (
    exploit_db_search,
    poc_search,
    memory_protection_analyzer,
    prerequisite_extractor,
)


# =====================================================================
# exploit_search.py unit tests
# =====================================================================

class TestExploitDbSearch:
    @patch("patchscope.agents.complexity_assessor.search_exploit_db")
    def test_finds_exploits(self, mock_search):
        mock_search.return_value = [
            {
                "title": "51674.c",
                "path": "exploits/linux/local/51674.c",
                "url": "https://www.exploit-db.com/exploits/51674",
                "edb_id": "51674",
                "source": "exploit-db",
            },
        ]
        result = exploit_db_search("CVE-2023-32233")
        assert result["exploit_count"] == 1
        assert result["exploits"][0]["source"] == "exploit-db"
        assert result["cve_id"] == "CVE-2023-32233"

    @patch("patchscope.agents.complexity_assessor.search_exploit_db")
    def test_no_exploits_found(self, mock_search):
        mock_search.return_value = []
        result = exploit_db_search("CVE-2099-99999")
        assert result["exploit_count"] == 0
        assert result["exploits"] == []

    @patch("patchscope.agents.complexity_assessor.search_exploit_db")
    def test_api_error_graceful(self, mock_search):
        import requests
        mock_search.side_effect = requests.ConnectionError("fail")
        result = exploit_db_search("CVE-2023-32233")
        assert "error" in result
        assert result["exploit_count"] == 0


class TestPocSearch:
    @patch("patchscope.agents.complexity_assessor.search_metasploit_modules")
    @patch("patchscope.agents.complexity_assessor.search_github_pocs")
    def test_finds_github_pocs_and_metasploit(self, mock_github, mock_msf):
        mock_github.return_value = [
            {
                "repo": "user/CVE-2023-32233",
                "url": "https://github.com/user/CVE-2023-32233",
                "description": "PoC for nf_tables use-after-free",
                "stars": 150,
                "language": "C",
                "source": "github",
            },
        ]
        mock_msf.return_value = [
            {
                "module_path": "modules/exploits/linux/local/nf_tables_uaf.rb",
                "url": "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/local/nf_tables_uaf.rb",
                "name": "nf_tables_uaf.rb",
                "source": "metasploit",
            },
        ]
        result = poc_search("CVE-2023-32233")
        assert result["github_poc_count"] == 1
        assert result["metasploit_module_count"] == 1
        assert result["total_public_exploits"] == 2
        assert result["has_weaponized_exploit"] is True

    @patch("patchscope.agents.complexity_assessor.search_metasploit_modules")
    @patch("patchscope.agents.complexity_assessor.search_github_pocs")
    def test_no_pocs_found(self, mock_github, mock_msf):
        mock_github.return_value = []
        mock_msf.return_value = []
        result = poc_search("CVE-2099-99999")
        assert result["total_public_exploits"] == 0
        assert result["has_weaponized_exploit"] is False

    @patch("patchscope.agents.complexity_assessor.search_metasploit_modules")
    @patch("patchscope.agents.complexity_assessor.search_github_pocs")
    def test_github_error_still_returns_msf(self, mock_github, mock_msf):
        import requests
        mock_github.side_effect = requests.ConnectionError("fail")
        mock_msf.return_value = [
            {"module_path": "modules/exploits/test.rb", "url": "url", "name": "test.rb", "source": "metasploit"},
        ]
        result = poc_search("CVE-2023-32233")
        assert result["github_poc_count"] == 0
        assert result["metasploit_module_count"] == 1


# =====================================================================
# Memory Protection Analyzer tests
# =====================================================================

class TestMemoryProtectionAnalyzer:
    def test_use_after_free_detects_heap_grooming(self):
        patch_content = (
            "static void nft_set_deactivate(struct nft_set *set) {\n"
            "    kfree(set);\n"
            "    /* use after free here */\n"
            "}\n"
        )
        result = memory_protection_analyzer("memory_corruption", patch_content)
        assert result["memory_protections_relevant"] is True
        assert "use_after_free" in result["corruption_subtypes"]
        assert any("Heap grooming" in t for t in result["bypass_techniques_needed"])

    def test_buffer_overflow_detects_aslr_dep(self):
        patch_content = (
            "void process(char *input) {\n"
            "    char buf[256];\n"
            "    strcpy(buf, input);  // overflow\n"
            "}\n"
        )
        result = memory_protection_analyzer("memory_corruption", patch_content)
        assert result["memory_protections_relevant"] is True
        assert "buffer_overflow" in result["corruption_subtypes"]
        assert any("ASLR" in t for t in result["bypass_techniques_needed"])
        assert any("DEP" in t for t in result["bypass_techniques_needed"])

    def test_race_condition_notes_timing(self):
        patch_content = (
            "spin_lock(&table->lock);\n"
            "/* critical section */\n"
            "spin_unlock(&table->lock);\n"
        )
        result = memory_protection_analyzer("race_condition", patch_content)
        assert any("timing" in note.lower() for note in result["analysis_notes"])

    def test_non_memory_bug_low_relevance(self):
        patch_content = "if user.is_admin:\n    return True\n"
        result = memory_protection_analyzer("auth_bypass", patch_content)
        assert result["memory_protections_relevant"] is False
        assert result["bypass_techniques_needed"] == []

    def test_architecture_passed_through(self):
        result = memory_protection_analyzer("memory_corruption", "kfree(obj);", "x86_64")
        assert result["architecture"] == "x86_64"

    def test_unknown_architecture_default(self):
        result = memory_protection_analyzer("memory_corruption", "kfree(obj);")
        assert result["architecture"] == "unknown"


# =====================================================================
# Prerequisite Extractor tests
# =====================================================================

class TestPrerequisiteExtractor:
    def test_detects_local_access_requirement(self):
        patch_content = "if (!capable(CAP_NET_ADMIN))\n    return -EPERM;\n"
        result = prerequisite_extractor("memory_corruption", patch_content)
        categories = [p["category"] for p in result["prerequisites"]]
        assert "local_access" in categories

    def test_detects_specific_config(self):
        patch_content = "#ifdef CONFIG_NF_TABLES\nstatic int nf_tables_init(void)\n#endif\n"
        result = prerequisite_extractor("memory_corruption", patch_content)
        categories = [p["category"] for p in result["prerequisites"]]
        assert "specific_config" in categories

    def test_detects_network_access(self):
        patch_content = "struct socket *sock = socket_create(AF_NETLINK, SOCK_RAW, 0);\n"
        cve_desc = "Remote attacker can send crafted netlink message"
        result = prerequisite_extractor(
            "memory_corruption", patch_content,
            cve_description=cve_desc,
        )
        categories = [p["category"] for p in result["prerequisites"]]
        assert "network_access" in categories

    def test_detects_timing_window(self):
        patch_content = "mutex_lock(&nft_net->commit_mutex);\n/* race condition */\n"
        result = prerequisite_extractor("race_condition", patch_content)
        categories = [p["category"] for p in result["prerequisites"]]
        assert "timing_window" in categories

    def test_attack_surface_overrides_default(self):
        result = prerequisite_extractor(
            "memory_corruption", "kfree(ptr);",
            attack_surface="local",
        )
        assert result["attacker_requirements"]["access_level"] == "local"

    def test_auth_gates_set_authentication(self):
        auth_gates = [{"has_auth_gate": True, "mechanism": "capable(CAP_NET_ADMIN)"}]
        result = prerequisite_extractor(
            "memory_corruption", "kfree(ptr);",
            auth_gates=auth_gates,
        )
        assert result["attacker_requirements"]["authentication"] == "single"

    def test_no_auth_gates_default_none(self):
        result = prerequisite_extractor("injection", "SELECT * FROM users WHERE id=?")
        assert result["attacker_requirements"]["authentication"] == "none"

    def test_user_interaction_detected(self):
        patch_content = "User must visit the malicious page and click the link"
        result = prerequisite_extractor("injection", "", cve_description=patch_content)
        assert result["attacker_requirements"]["user_interaction"] == "required"

    def test_memory_corruption_constraints(self):
        result = prerequisite_extractor(
            "memory_corruption", "use_after_free in nft_set",
        )
        assert any("memory layout" in c.lower() for c in result["exploitation_constraints"])

    def test_race_condition_constraints(self):
        result = prerequisite_extractor("race_condition", "spin_lock timing issue")
        assert any("timing" in c.lower() for c in result["exploitation_constraints"])

    def test_injection_constraints(self):
        result = prerequisite_extractor("injection", "SQL query param")
        assert any("payload" in c.lower() or "sanitization" in c.lower()
                    for c in result["exploitation_constraints"])


# =====================================================================
# Branching scenario tests
# =====================================================================

class TestBranchingScenarios:
    """Verify tool outputs produce the signals that drive agent branching."""

    @patch("patchscope.agents.complexity_assessor.search_exploit_db")
    def test_public_exploit_lowers_complexity(self, mock_search):
        """Public exploit found → agent should rate complexity as LOW."""
        mock_search.return_value = [
            {"title": "51674.c", "path": "exploits/linux/local/51674.c",
             "url": "https://www.exploit-db.com/exploits/51674",
             "edb_id": "51674", "source": "exploit-db"},
        ]
        result = exploit_db_search("CVE-2023-32233")
        assert result["exploit_count"] > 0  # Agent: complexity = low

    @patch("patchscope.agents.complexity_assessor.search_exploit_db")
    def test_no_public_exploit_higher_complexity(self, mock_search):
        """No public exploit → agent should rate complexity higher."""
        mock_search.return_value = []
        result = exploit_db_search("CVE-2023-32233")
        assert result["exploit_count"] == 0  # Agent: complexity >= medium

    @patch("patchscope.agents.complexity_assessor.search_metasploit_modules")
    @patch("patchscope.agents.complexity_assessor.search_github_pocs")
    def test_metasploit_module_signals_weaponized(self, mock_github, mock_msf):
        """Metasploit module → agent should note weaponized exploit exists."""
        mock_github.return_value = []
        mock_msf.return_value = [
            {"module_path": "modules/exploits/linux/local/test.rb",
             "url": "url", "name": "test.rb", "source": "metasploit"},
        ]
        result = poc_search("CVE-2023-32233")
        assert result["has_weaponized_exploit"] is True  # Agent: reliable exploitation

    def test_memory_corruption_triggers_protection_analysis(self):
        """memory_corruption bug_class → agent must run memory_protection_analyzer."""
        result = memory_protection_analyzer(
            "memory_corruption",
            "kfree(set); /* UAF */",
        )
        assert result["memory_protections_relevant"] is True  # Agent: analyze bypasses

    def test_injection_skips_memory_analysis(self):
        """injection bug_class → memory protections not relevant."""
        result = memory_protection_analyzer(
            "injection",
            "query = 'SELECT * FROM users WHERE id=' + user_input",
        )
        # injection doesn't set protections_relevant unless patterns found
        assert result["bypass_techniques_needed"] == []

    def test_race_condition_notes_unreliability(self):
        """race_condition → agent should note probabilistic exploitation."""
        result = memory_protection_analyzer(
            "race_condition",
            "mutex_lock(&lock); /* critical section */",
        )
        assert any("timing" in note.lower() or "multiple attempts" in note.lower()
                    for note in result["analysis_notes"])

    def test_prerequisites_drive_complexity(self):
        """Many prerequisites → agent should rate complexity higher."""
        patch_content = (
            "if (!capable(CAP_NET_ADMIN)) return -EPERM;\n"
            "#ifdef CONFIG_NF_TABLES\n"
            "mutex_lock(&nft_net->commit_mutex);\n"
        )
        result = prerequisite_extractor("memory_corruption", patch_content)
        assert result["prerequisite_count"] >= 2  # Agent: higher complexity

    def test_no_prerequisites_lower_complexity(self):
        """No special prerequisites → complexity stays based on other factors."""
        result = prerequisite_extractor("injection", "return user_input")
        assert result["prerequisite_count"] == 0  # Agent: doesn't increase complexity


# =====================================================================
# Integration tests (require network — mark so they can be skipped)
# =====================================================================

@pytest.mark.integration
class TestIntegrationComplexity:
    """Full complexity assessment with real APIs."""

    def test_cve_2023_32233_exploit_search(self):
        """CVE-2023-32233: search for public exploits."""
        result = exploit_db_search("CVE-2023-32233")
        print(f"\n  Exploit-DB results: {result['exploit_count']}")
        for e in result["exploits"]:
            print(f"    - {e['title']}: {e['url']}")

    def test_cve_2023_32233_poc_search(self):
        """CVE-2023-32233: search for PoCs and Metasploit modules."""
        result = poc_search("CVE-2023-32233")
        print(f"\n  GitHub PoCs: {result['github_poc_count']}")
        for p in result["github_pocs"][:3]:
            print(f"    - {p['repo']} ({p['stars']} stars): {p['description'][:80]}")
        print(f"  Metasploit modules: {result['metasploit_module_count']}")
        for m in result["metasploit_modules"]:
            print(f"    - {m['module_path']}")

    def test_cve_2023_32233_memory_analysis(self):
        """CVE-2023-32233: analyze memory protections for UAF."""
        patch_content = (
            "-\tnft_set_deactivate(ctx, set);\n"
            "+\tif (nft_set_is_anonymous(set) &&\n"
            "+\t    atomic_read(&set->nelems) == 0)\n"
            "+\t\tnft_set_deactivate(ctx, set);\n"
        )
        result = memory_protection_analyzer("memory_corruption", patch_content)
        print(f"\n  Memory protections relevant: {result['memory_protections_relevant']}")
        print(f"  Corruption subtypes: {result['corruption_subtypes']}")
        print(f"  Bypass techniques: {result['bypass_techniques_needed']}")
        print(f"  Notes: {result['analysis_notes']}")
