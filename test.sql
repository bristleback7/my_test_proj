update IV_THREAT_ADVERSARIES 
set
        ADVERSARY_OBJECTIVE = 'Remote Access Trojan (RAT)',
        ADVERSARY_SUBCATEGORY = 'Trojan',
        ADVERSARY_TECH_DETAILS = 'XWorm V5.6 is a Remote Access Trojan (RAT) known for its advanced capabilities, including keylogging, screen capturing, and remote control of the infected machine. It typically spreads through phishing emails containing a .rar attachment. When the recipient opens this attachment, it extracts an executable (.exe) file. Once executed, this file initiates a process injection, allowing the malware to embed itself into legitimate processes running on the system. This technique helps XWorm evade detection by security software.',
where ADVERSARY_ID = 558;

update IV_INDICATORS_OF_COMPROMISE
set
        ADVERSARY_DESCRIPTION  = 'XWorm is a sophisticated Remote Access Trojan (RAT) and multifunctional malware family sold and distributed as malware-as-a-service since at least 2022. It is favored by both cybercriminal groups and advanced persistent threat actors due to its modular architecture, wide array of capabilities, and flexible delivery methods. Known for frequent updates and evasion improvements, XWorm is deployed in campaigns targeting individuals, enterprises, and government entities across various regions.',
        ADVERSARY_OBJECTIVE    = 'Remote Access Trojan (RAT)',
        ADVERSARY_TECH_DETAILS = 'XWorm V5.6 is a Remote Access Trojan (RAT) known for its advanced capabilities, including keylogging, screen capturing, and remote control of the infected machine. It typically spreads through phishing emails containing a .rar attachment. When the recipient opens this attachment, it extracts an executable (.exe) file. Once executed, this file initiates a process injection, allowing the malware to embed itself into legitimate processes running on the system. This technique helps XWorm evade detection by security software.'
        ADVERSARY_SUBCATEGORY  = 'Trojan',
where ADVERSARY_NAME = 'Xworm';

update IV_THREAT_ADVERSARIES (ADVERSARY_ID, CREATED_BY, CREATED_ON, LAST_MODIFIED_ON,
                                                   LAST_MODIFIED_BY, ADVERSARY_DESCRIPTION, ADVERSARY_NAME,
                                                   ADVERSARY_OBJECTIVE, ADVERSARY_SUBCATEGORY, ADVERSARY_TECH_DETAILS,
                                                   ADVERSARY_TYPE, ORG_ID)
VALUES (558, 'SYSTEM', '2024-11-29 09:05:00', '2024-11-29 09:05:00', 'SYSTEM',
        'XWorm is a sophisticated Remote Access Trojan (RAT) and multifunctional malware family sold and distributed as malware-as-a-service since at least 2022. It is favored by both cybercriminal groups and advanced persistent threat actors due to its modular architecture, wide array of capabilities, and flexible delivery methods. Known for frequent updates and evasion improvements, XWorm is deployed in campaigns targeting individuals, enterprises, and government entities across various regions.',
        'XWorm', 'Remote access, data theft, ransomware deployment, DDoS attacks', 'Remote Access Trojan (RAT)',
        'XWorm is a modular, malware-as-a-service family first seen around 2022, used as a Remote Access Trojan with capabilities including keylogging, screen capture, Metamask/Telegram session hijacking, cryptocurrency address replacement, ransomware, DDoS, HVNC and file uploads. It employs multi-stage, deceptive infection chains using a variety of droppers/loaders—PowerShell, batch, VBS, .hta, .lnk, script files, office macros, and obfuscated loaders—to evade detection, with reflective DLL injection and loader variants. It spreads via phishing emails, paste.ee–hosted payloads, GitHub, and social-engineered executable filenames. Campaigns have delivered XWorm alongside other RATs, and it supports stolen/cracked distribution models. Targets include credential theft, persistence, data exfiltration, and remote command execution.',
        'Threat Families', 254);
