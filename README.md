# Azure MFA Bombing Threat Detection with Microsoft Sentinel

**Possible IAM MFA bombing from Microsoft 2FA notifications**

```
SigninLogs
| where ResultType == 500121
| extend AuthResult = tostring(parse_json(AuthenticationDetails)[1].authenticationStepResultDetail)
| where AuthResult in ("MFA denied; user declined the authentication", "MFA denied; user did not respond to mobile app notification") or Status has "MFA denied; Phone App Reported Fraud"
| where parse_json(AuthenticationDetails)[1].authenticationStepRequirement == "User, MultiConditionalAccess"
| where isnotempty(AlternateSignInName)
| summarize ['MFA_Actions']=make_list(AuthResult), ['MFATotalFailed']=count() by AppDisplayName, Identity, UserPrincipalName, bin(TimeGenerated, 12h)
| where ['MFATotalFailed'] > 3
//Detect MFA bombing 4 or more denied or ignored MFA tokens generated within 24 hours
| sort by MFATotalFailed
| project TimeGenerated, Identity, UserPrincipalName, AppDisplayName, MFA_Actions, MFATotalFailed
```

# License
Berkeley Software Distribution (BSD)

# Author
[Jeroen van Kessel](https://twitter.com/jeroenvkessel) | [cryptsus.com](https://cryptsus.com) - we craft cyber security solutions
