# Basic Static Analysis Automation

This simple tool is used to automate information extraction during basic analysis which is performed during malware analysis.

This tool is based on `Radare2` RE framework and `YARA` for getting static information about the binary and detecting packing and encryption algorithms.

Also, this tool uses `VirusTotla` API to scan the binary against security vendors and also run the malware on `Microsoft Sysinternals Sandbox` to automate dynamic analysis and get more information about binary behavior.

## Output from the tool:

- Get static analysis information from Radare2
    - Strings
    - APIs
    - Hashes
    - Sections
    - Resources
    - DLLs
    - General information
    - Exports (if the binary is DLL)
    
- Check for packers and cryptos using YARA rules

- Get all vendors that mark the binary as a malicious file from VirusTotal

- Get a binary's behavior report from Microsoft Sysinternals Sandbox

## Usage:

Open the terminal inside the root directory of the tool and fire this command:

<code>
python Odissa.py
</code>

<br>

## Notes:

You can add more information from `Radare2` by just adding the command and file name for the output.

Also, you can make your VT API key hard-coded to make the usage more easy.

## References/Resources:

- [Detect packers and cryptos with YARA and pefile](https://isleem.medium.com/detect-malware-packers-and-cryptors-with-python-yara-pefile-65bf3c15be78)

- [Radare2 Tutorial](https://www.youtube.com/playlist?list=PLg_QXA4bGHpvsW-qeoi3_yhiZg8zBzNwQ)

- [Introduction to r2pipe API](https://www.youtube.com/watch?v=UUJzeWzyqq0)

- [VirusTotal API documenatation](https://developers.virustotal.com/reference/api-v2-v3-migration-guide)

