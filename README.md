# Datacom-Cyber-Security-Job-Simulation

## Objective: The aim of this project is to investigate a cyberattack and conduct a comprehensive risk assessment with Datacom.

- Gain hands-on experience with real-world cybersecurity threats.

- Utilize Open-Source Intelligence (OSINT) tools to investigate Advanced Persistent Threats (APTs), specifically focusing on APT34.

- Apply the MITRE ATT&CK Framework to identify and categorize threats and vulnerabilities.

- Assess and document the impact of cyberattacks on organizational information security.

- Develop a defense strategy to prevent future attacks on clients' networks and systems.





### Skills Learned

- OSINT Techniques: Gained proficiency in gathering information on threat actors using OSINT tools such as Shodan, Maltego, and theharvester.

- Threat Intelligence & Analysis: Investigated and analyzed APT34, a well-known threat group, to assess its tactics, techniques, and procedures (TTPs) for identifying risks to organizational security.

- MITRE ATT&CK Framework: Applied the framework to map out attack vectors, allowing for the identification and mitigation of security risks.

- Risk Assessment & Mitigation: Conducted a detailed risk assessment of potential vulnerabilities, determining risk ratings based on likelihood and consequences, and proposed risk mitigation strategies.

- Incident Response: Documented and analyzed an incident where customer data and intellectual property were stolen, outlining key steps to remediate the breach and prevent future attacks.

- Report Writing & Documentation: Compiled findings into a comprehensive report, which included risk scenarios, risk ratings, and mitigation strategies tailored for the client.



### Tools Used

- OSINT Tools: Shodan, Maltego, theHarvester

- MITRE ATT&CK Framework: Used for identifying attack vectors and categorizing threats

- Risk Matrix: Developed to assess likelihood, consequences, and risk ratings for potential attack scenarios

- Risk Assessment Tools: Padlock analogy and other standard tools to evaluate security posture and propose additional measures.


## Steps
**Task 1: APT breach**: Analysing the impact on information security - Investigate a cyber attack and produce a comprehensive report documenting your findings and outline key recommendations for improving a client's cybersecurity posture.

Background: In this task, you will be stepping into the role of a cybersecurity consultant here at Datacom. One of our leading tech corporation clients has fallen prey to a sophisticated cyberattack by a notorious Advanced Persistent Threat (APT) group known as APT34. The attack, believed to be sponsored by a foreign government, has left the organisation's network compromised, and valuable customer data and intellectual property has been stolen.Your mission is to conduct initial research on this APT group, APT34, and assess the extent of the breach's impact on the organisation's information security. But fear not, for you will be provided with all the necessary tools required to understand cybersecurity concepts and principles, including cyberthreats, attack methods, and the importance of confidentiality, integrity and availability of information. In addition, you will also be familiarised with APT34's tactics, techniques and procedures (TTPs) and the common vulnerabilities they exploit to gain access to networks.The objective of this task is to help our client conduct an initial investigation into APT34 and evaluate the potential impact of the attack on the organization. As a result, you will need to produce a comprehensive report documenting your findings and outlining key recommendations for improving the organisation's cybersecurity posture.

--->As a cybersecurity professional, I successfully utilized various Open-Source Intelligence (OSINT) tools and techniques to gather critical information on APT34. By leveraging the available resources and conducting independent research, I was able to compile detailed intelligence on the group's activities, including their tactics, techniques, and procedures (TTPs). Additionally, I applied the MITRE ATT&CK Framework to systematically identify and categorize APT34's cyberthreats. Using this framework, I developed a comprehensive defense strategy tailored to protect the client's networks and systems against future attacks, enhancing their overall security posture.

I used the following OSINT tools to gather information about APT34:

[MITRE ATT&CK](https://attack.mitre.org/)

[Cybersecurity and Infrastructure Security Agency (CISA)](https://www.cisa.gov/)

[US-CERT](https://www.us-cert.gov/)

[Mandiant Security Blog](https://www.mandiant.com/resources/blog)

[CrowdStrike](https://www.crowdstrike.com/)

[Recorded Future](https://www.recordedfuture.com/)

[CyberScoop](https://www.cyberscoop.com/)

[Dark Reading](https://www.darkreading.com/)

[The CyberWire](https://thecyberwire.com/)

[SecureWorks ](https://www.secureworks.com/)

[ThreatConnect](https://www.threatconnect.com/) 

[Kaspersky Lab](https://www.kaspersky.com/)

[Symantec Threat Intelligence](https://www.symantec.com/threat-intelligence)


This is my research on APT34:

*Ref 1.1: APT34 MITRE ATT&CK*
<img width="1440" alt="T1-APT34 MITRE ATT CK" src="https://github.com/user-attachments/assets/7e7ae269-a5fb-4a4c-b0ba-311569198139">



1. What is their history?

APT34, also known as OilRig, is an Advanced Persistent Threat (APT) group that has been active since at least 2014. It has been linked to numerous cyber espionage campaigns that primarily target organizations in the Middle East. The group is known for highly strategic, long-term campaigns where it remains hidden in networks for extended periods, exfiltrating data and conducting espionage activities. APT34 primarily focuses on sectors such as telecommunications, government, financial institutions, and critical infrastructure.



2. Which nation/state are they associated with?

APT34 is suspected to be linked to Iran. Multiple reports, including those from cybersecurity firms and government entities, suggest that APT34 operates under or is associated with Iran's government or military apparatus, focusing on advancing Iran's strategic objectives in cyber warfare and espionage.



3. Do they target specific industries?

Yes, APT34 targets specific industries that align with geopolitical and economic interests. The industries commonly targeted include:

•Telecommunications: They target telecom companies to monitor communications or compromise network infrastructure.

•Government agencies: Focus on accessing sensitive state information and diplomatic communications.

•Financial institutions: Attempts to gather sensitive financial data or disrupt banking systems.

•Critical infrastructure: Includes energy and oil sectors, where attacks could impact energy distribution and national security.

•Aerospace and Defense: Steal sensitive technical data for military or technological advancements.



4. What are their motives?

The primary motive of APT34 is cyber espionage. The group focuses on gathering intelligence from sectors vital to national security, defense, economic strategy, and geopolitical interests. Their targets often include government organizations, corporations, and critical infrastructure to gain insights that can be used to enhance their nation’s position in international affairs. Additionally, they aim to disrupt operations or gather intelligence for strategic advantages in negotiations or conflicts.



5. What are the TTPs they use to conduct their attacks?

APT34’s Tactics, Techniques, and Procedures (TTPs) have been documented through investigations and threat analysis reports. The group uses a mix of custom-developed malware, publicly available tools, and spear-phishing techniques. They often leverage vulnerabilities in Microsoft products and web servers. Their TTPs align with various phases of the MITRE ATT&CK framework as follows:

•Initial Access:

Spear-phishing: Delivering malicious documents or links via email to gain initial access.
Exploitation of Public-Facing Applications: Targeting vulnerabilities in web applications, particularly with Microsoft Exchange.

•Execution:

PowerShell: They use PowerShell scripts for execution of malicious code once inside the network.

•Persistence:

Web Shells: Installed on compromised servers to maintain long-term access.

•Privilege Escalation:

Exploitation of Vulnerabilities: APT34 often exploits vulnerabilities like CVE-2017-11882 (Microsoft Office vulnerability).

•Defense Evasion:

Obfuscated Files or Information: APT34 uses various obfuscation techniques to evade detection, such as encoding scripts and hiding payloads.

•Credential Access:

Credential Dumping: Uses tools like Mimikatz to extract credentials from memory or databases.

•Discovery:

Network Service Scanning: Identifying network services running in the environment to map the infrastructure.

•Lateral Movement:

Pass-the-Hash: Reusing stolen credentials to move laterally across the network.

•Exfiltration:

Encrypted Channels: Using SSL or custom encryption to exfiltrate data without detection.




6. What security measures could the client implement to defend against cyberattacks conducted by this APT?

To defend against APT34’s sophisticated attacks, the client must implement a layered defense strategy based on the MITRE ATT&CK framework and best practices in cybersecurity. The following are recommended security measures:

a. Email Security and Awareness

Implement advanced email filtering and sandboxing to detect spear-phishing emails.
User awareness training to recognize suspicious emails and avoid clicking on potentially malicious links or attachments.

b. Patching and Vulnerability Management

Regularly update and patch critical software vulnerabilities, especially in web-facing applications like Microsoft Exchange.
Perform routine vulnerability scans and penetration testing to identify and mitigate security gaps.

c. Endpoint Detection and Response (EDR)

Deploy Endpoint Detection and Response (EDR) solutions to monitor and respond to malicious activity on endpoints.
Implement application whitelisting to prevent unauthorized execution of PowerShell scripts or other malicious executables.

d. Network Segmentation

Implement network segmentation to isolate critical systems, ensuring that a compromise of one part of the network doesn’t lead to full access.
Use firewalls and intrusion prevention systems (IPS) to monitor and filter network traffic, detecting unusual patterns.

e. Multi-factor Authentication (MFA)

Enforce multi-factor authentication (MFA) for all users, particularly for privileged accounts, to make credential theft less effective.

f. Privileged Access Management (PAM)

Implement PAM solutions to restrict and monitor the use of administrator privileges across systems.
Regularly rotate credentials and limit the number of privileged accounts.

g. Advanced Threat Detection

Deploy Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS) that utilize signature-based and anomaly-based detection to spot indicators of compromise (IOCs) associated with APT34.
Implement Security Information and Event Management (SIEM) tools that incorporate threat intelligence feeds to detect APT34’s TTPs.

h. Incident Response Plan

Establish a comprehensive incident response plan to detect, respond, and recover from cyber incidents.
Conduct regular tabletop exercises to ensure that the team is prepared for real-world attack scenarios.

i. Data Encryption and Monitoring

Use data encryption for sensitive data both at rest and in transit to mitigate the impact of data exfiltration.
Implement DLP (Data Loss Prevention) tools to monitor and block unauthorized exfiltration of sensitive data.

j. Continuous Monitoring and Threat Hunting

Implement continuous monitoring with a focus on APT-like behavior (e.g., lateral movement, unusual data transfers).
Perform proactive threat hunting using indicators of compromise (IOCs) related to APT34 to detect hidden activity within the network.

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

**Task 2: Cybersecurity risk assessment** - Complete a risk assessment for a client and help them define the context, assess their risk matrix, and identify potential risk scenarios

Background: Understanding the TTPs of APT34 helps identify specific vulnerabilities and attack vectors that could be exploited. This has laid a solid foundation for the next task, which is to conduct a comprehensive risk assessment for the client. The client has a fence around the perimeter of its property and a padlock on its entrance gate to prevent unauthorised access. However, the leadership team is concerned about potential risks and vulnerabilities that could compromise the security of its information and systems.This involves identifying, evaluating and prioritising potential security threats and vulnerabilities to determine the level of risk and develop a plan to mitigate those risks. During the risk assessment, you will need to identify the assets that need to be protected, define the risk matrix and identify potential risk scenarios. You will assess the risk ratings for each scenario, both with and without existing measures in place. Finally, you will provide a risk assessment report to the client summarising your findings and recommendations for mitigating risks and improving the institution's security posture.


---> In this task, I will be documenting the client's risk position using the padlock analogy as an example. 

I used the following links as a reference to conduct a detailed, organised and structured risk assessment:

•[NIST Guide for Conducting Risk Assessments](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-30r1.pdf)

•[SO/IEC 27001:2013 Information technology - Security techniques - Information security management systems - Requirements](https://www.iso.org/standard/54534.html)

•[SANS Institute: Risk Assessment Methodologies](https://www.sans.org/reading-room/whitepapers/auditing/risk-assessment-methodologies-32)

•[Guide to Getting Started with a Cybersecurity Risk Assessment](https://www.cisa.gov/sites/default/files/video/22_1201_safecom_guide_to_cybersecurity_risk_assessment_508-r1.pdf)

•[The Open Group Risk Management Standard](https://www.opengroup.org/forum/security-forum-0/securityriskmanagement)



This is the principle I used for generating the risk assessment report:

1. Define the context: I defined the context by identifying the critical assets that needed protection, which included sensitive information, customer data, financial records, and other key assets vital to the client's business operations.

2. Define the risk matrix: I developed a comprehensive risk matrix, where I assessed the likelihood and consequence of each potential risk scenario. The likelihood represented the probability of the risk occurring, while the consequence denoted the severity of the impact. I calculated the risk rating by multiplying the likelihood and consequence, offering a clear measure of the overall risk posed by each scenario.

3. Define three risk scenarios: I identified three specific risk scenarios relevant to the client, including a cyberattack, employee negligence, and a natural disaster. These scenarios highlighted the primary threats to the client's critical assets.

4. Assess risk rating for each risk scenario: I assessed the inherent risk rating for each of these scenarios, assuming no security measures were in place (without the fence and padlock analogy). This provided a baseline of the raw risk before any mitigation strategies were applied.

5. Assess risk rating for each risk scenario with existing measures: I then reassessed the risk ratings by factoring in the client’s existing security measures, such as firewalls, access controls, and incident response protocols. This helped evaluate the current risk posture with protections already in place (with fence and padlock analogy).

6. Assess risk levels for each risk scenario with additional measures: To further reduce risks, I recommended additional security measures. After incorporating these recommendations, I recalculated the target risk ratings, reflecting a more secure environment.

7. Create a risk assessment report: Finally, I compiled a detailed risk assessment report for the client. This report summarized the key findings, outlined the risk mitigation strategy, and provided clear recommendations for future implementation to enhance the client’s cybersecurity posture.



*Ref 2.1: Risk Context*
<img width="900" alt="T2-Context" src="https://github.com/user-attachments/assets/090478d7-21ea-4df9-9142-81fd60ea4502">


*Ref 2.2: Risk Matrix*
<img width="1108" alt="T2-Risk Matrix" src="https://github.com/user-attachments/assets/b972bf6b-72c6-4b9b-9221-4f0c5a595f73">



*Ref 2.3: Risk Assesment Report*
<img width="1440" alt="T2-Risk Assessment" src="https://github.com/user-attachments/assets/bb2596dd-51c5-4a16-8b31-6e5d2cfa7e93">



## Conclusion
The Datacom Cybersecurity Job Simulation provided an invaluable hands-on experience, allowing for the practical application of cybersecurity theories and principles. The project enabled the identification of significant risks posed by APT34, including its motives, attack methods, and the common vulnerabilities it exploits. By leveraging OSINT tools and the MITRE ATT&CK Framework, a comprehensive defense strategy was developed to bolster the client's security posture against advanced threats. This simulation enhanced my skills in threat analysis, risk assessment, and strategic security planning, preparing me to handle real-world cybersecurity challenges.
