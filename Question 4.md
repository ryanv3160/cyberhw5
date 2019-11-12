##OWASP Top 10 2010, 2013 and 2017 Injection Attacks

|2010                                        |2013                                       |2017                                       |
|:-------------------------------------------|:------------------------------------------|:------------------------------------------|
|Injection                                   |Injection                                  |Injection                                  |
|XSS                                         |Broken Authenticaion and Session Management|Broken Authentication                      |
|Broken Authentication and Session Management|XSS                                        |Sensitive Data Exposure                    |
|Insecure Direct Object References           |Insecure Direct Object References          |XXE                                        |
|CSRF                                        |Security Misconfiguration                  |Broken Access Control                      |
|Security Misconfiguration                   |Sensitive Data Exposure                    |Security Misconfiguration                  |
|Insecure Cryptographic Storage              |Missing Function Level Access Control      |XSS                                        |
|Failure to Restrict URL Access              |CSRF                                       |Insecure Deserialization                   |
|Insufficient Transport Layer Protection     |Using Components with Known Vulnerabilities|Using Components With Known Vulnerabilities|
|Unvalidated Redirects and Forwards          |Unvalidated Redirects and Forwards         |Insufficient Logging & Monitoring          |

##Discuss how Injection and XSS attacks have changed their places on the list

In 2010, Injection and XSS were in positions 1 and 2, respectively. Injection remained at the same position of the list in both 2013 and 2017. However, XSS moved from position 2 to 3 and then 7. 

Injection was the top threat in 2010 because almost any source of data could be an injection vector, as it is the responsibility of the interpreter to detect whether the injected data is from a trusted or untrusted source. These flaws can be caused by various queries that an attacker may input into various fields to access functionality they should be prohibited from accessing. This remains the top threat through 2017 because it not only exists as a vulnerability in legacy systems, but can also be easily enabled in new systems where programmers fail to bind variables, avoid dynamic variables, validate input, or fail to escape user-supplied input. Because there are so many different interpreters, database types, and different possible exploitations, injection requires a lot of work on the programmer's end to prevent.

Though XSS was still prevalent as of 2017, its spot near the top was replaced due to the nature of XSS attacks that user sessions be hijacked one user at a time. So, although the attacks are still common, the potential for other types of attacks to expose massive amounts of data in one fell swoop makes them bigger threats than XSS. For example, Broken Authentication can take advantage of authentication problems that are system-wide and apply to each user. Sensitive Data Exposure can capture massive amounts of unprotected data as it's in transit. XXE is a threat because a malicious XML file can potentially extract all data from the application's server. The Broken Access Control and Security Misconfiguration weaknesses are similar in that they can expose large amounts of data. Because there now exist tools that can capture a ton of data rather than just one user's session at a time means that being vulnerable in any of these other ways could have a much larger impact.






