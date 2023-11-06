In the realm of identity management solutions, Okta stands as a beacon of trust, serving a multitude of global enterprises. With offerings like two-factor authentication (2FA) and Single Sign-On (SSO), the company caters to an impressive clientele that includes major corporations such as T-Mobile, jetBlue, Sonos, and many more. 
# The Breach
Companies that specialize in identity management, like Okta, often find themselves in the crosshairs of cyber adversaries due to the pivotal role they play in securing access to high-value resources. This vulnerability came to the forefront in October 2023 when Okta reported a concerning incident. The company stated, "We have identified adversarial activity that exploited access to a stolen credential for entry into Okta's support case management system. The threat actor successfully accessed files that had been uploaded by select Okta customers as part of recent support cases."

But what exactly were these files? They were **HAR** files—HTTP Archive files, which serve as logs of web browsers' interactions with websites. These files often contain sensitive data, including cookies and session tokens, which, when in the wrong hands, can be leveraged to impersonate legitimate users. One might assume that a company of Okta's caliber would have robust session validation in place, but, in this case, that assumption proved to be incorrect.

Among the organizations impacted by this breach was BeyondTrust, a company whose HAR files were compromised just 30 minutes after submission to Okta's support team. Within one of these files resided a session cookie linked to an administrative account. This account was fortified with custom security policies that initially thwarted the attacker's efforts. However, the attacker adapted by pivoting toward an API that lacked the same level of protective measures as the administrative console. Subsequently, the attacker introduced a backdoor into the system, but their activities were quickly detected and remediated thanks to the maturity of BeyondTrust's security team.

# We're Working On It - May 2022
Rewind to May 2022, when I was engaged in an internal penetration test. Our focus? Evaluating the monitoring and detection capabilities of Okta's logs, with a particular interest in geo location alerting. We aimed to determine whether anomalies in user login locations, such as a user logging in from the east coast when their typical location was on the west coast, would trigger alerts. While the likelihood of compromising credentials and 2FA was low, our interest was piqued by the potential threat vector.

It's worth noting that attackers often abuse user accounts by stealing web session cookies. Mitre has classified this type of attack as [T1539](https://attack.mitre.org/techniques/T1539/), and preventing it is relatively straightforward with proper [session management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html). Our test involved emulating threat actor tactics and techniques. A colleague authenticated to Okta using their credentials and shared their cookies with me. I set up a quick Windows host in another country via DigitalOcean, imported the cookies, and to my surprise, I was authenticated, I had a duplicate session as my colleague. The cookie bypassed every authentication mechanism. It was easy to import the cookies and terrifying that I was authenticated as my colleague.

But this wasn't the end of our investigation. I took it a step further by asking my colleague to log out. To my astonishment, I remained authenticated and could still access resources beyond Single Sign-On (SSO).

I proceeded to contact our Okta representative to inform them about the issue. We set up a meeting to discuss the matter. During the meeting, I showcased the vulnerability to our sales representative and a few of their engineers. At the end of my demo, they promised to look into the matter.

A few days later, we received the following response:
<pre>
  <code class="">
"As a web application, Okta relies on the security of the browser and operating system environment to protect against endpoint attacks such as malicious browser plugins or cookie stealing.  If an attacker has a foothold on your endpoint that would allow them access to user cookies, they would also have the ability to deploy malware or other methods to compromise the downstream applications.  We recommend using fleet management tools such as JAMF to ensure your endpoints are appropriately protected and hardened.  
  
Okta is monitoring the development of session cookie protections such as Token Binding. While browser-based security options mature, Customers may also wish to use Okta’s Device Trust capability to ensure that critical applications are only accessed from managed systems, or integrate Okta system logs with their SIEM tool to allow for aggregation of cloud service logs and detection of cookie-reuse attacks."
  </code>
</pre>

To me, this response was unacceptable. Browser and OS security alone do not prevent cookies from being stolen, and fleet management tools are hardly a comprehensive solution. Furthermore, placing the responsibility for detecting session hijacking on the consumer is an impractical approach, as not every customer possesses a mature Security Information and Event Management (SIEM) system. Even in cases where organizations have robust security measures in place, like BeyondTrust, attackers still manage to hijack sessions. None of the remedies proposed by Okta would have prevented this breach.

I responded with the following:
<pre>
  <code class="">
The issues that we have is a user could go to a legitimate site that has been compromised via XSS or another way and their cookies would be stolen. EDR would not do anything to prevent this and each company that uses OKTA would need to have a mature SIEM system and create detection. Is there a control in OKTA to de auth someone if this is observed?

What we would like to see is a better solution where OKTA is generating an alarm that says “Hey this user agent/IP changed something suspicious is occurring” and if that alarm exists have an option that could be set by the company to de-authenticate the user.

This is a current risk and adversaries are stealing cookies and breaching companies using this technique. There is a technique documented by MITRE https://attack.mitre.org/techniques/T1539/
  </code>
</pre>

Three weeks later, Okta replied with the following:
<pre>
  <code class="">
"Okta is actively working towards the mitigation of session cookie theft by adding session cookie protections such as Token Binding; however, Okta does not have an estimated timeline for completion.

Customers that have integrated Okta system logs with their SIEM tool can leverage Okta's API to terminate session where suspicious activity related to an Okta user is detected. 

In addition, current customers can leverage Okta's Device Trust capabilities, which enables organizations to protect their sensitive corporate resources by allowing access from only managed devices."
  </code>
</pre>

Okta suggested that their Device Trust capabilities, combined with ongoing work on session cookie theft, would address the issue. Come to find out it was not. Okta had **17** months to remediate this vulnerability, and sadly it took a breach for them to make quick work of the vulnerability.  
