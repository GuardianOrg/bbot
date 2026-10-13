from pathlib import Path

from bbot.modules.medusa import medusa


def test_medusa_default_wordlist_is_packaged_and_complete():
    wordlist = Path(medusa.options["snmp_wordlist"])
    assert wordlist.is_file()
    lines = wordlist.read_text().splitlines()
    assert len(lines) >= 100
    assert "public" in lines
    assert "private" in lines
