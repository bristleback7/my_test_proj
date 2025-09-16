update IV_THREAT_ADVERSARIES 
set
        ADVERSARY_OBJECTIVE = 'Remote Access Trojan (RAT)';

update IV_INDICATORS_OF_COMPROMISE
set
        ADVERSARY_DESCRIPTION  = 'XWorm is a sophisticated Remote Access Trojan (RAT) and multifunctional malware family sold and distributed as malware-as-a-service since at least 2022. It is favored by both cybercriminal groups and advanced persistent threat actors due to its modular architecture, wide array of capabilities, and flexible delivery methods. Known for frequent updates and evasion improvements, XWorm is deployed in campaigns targeting individuals, enterprises, and government entities across various regions.',
        ADVERSARY_OBJECTIVE    = 'Remote Access Trojan (RAT)',
        ADVERSARY_SUBCATEGORY  = 'Trojan',
        ADVERSARY_TECH_DETAILS = 'XWorm V5.6 is a Remote Access Trojan (RAT) known for its advanced capabilities, including keylogging, screen capturing, and remote control of the infected machine. It typically spreads through phishing emails containing a .rar attachment. When the recipient opens this attachment, it extracts an executable (.exe) file. Once executed, this file initiates a process injection, allowing the malware to embed itself into legitimate processes running on the system. This technique helps XWorm evade detection by security software.'
where ADVERSARY_NAME = 'Xworm';