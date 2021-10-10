# ad_audit

This script does query Active Directory and creates an HTML-Report of the results.
It does not require any software to be installed, it will run out of the box.
However, you will need Powershell v5.x and it has to be run on a Domain-Controller directly.

**As always: Do not run this script without explicit permission of the network owner!**

## Usage:

Show all available options:

`powershell -ep bypass .\ad_audit.ps1`

```

Option          Beschreibung
------          ------------
-gpo            generate a separate report of GPOs
-smb            show smb specific configuration
-passwordpolicy show the domain default password policy
-hosts          list old servers and clients
-dcs            list all domain controllers
-users          list old / unused users
-admins         list users that may have admin rights
-acl            list all Domain-ACLs
-keeplogs       keep old reports
-lang           Report language | de = deutsch (default if not set)| en = english
-allchecks      run all checks
```


All results will be stored in C:\report unless you did not specify a different path in the script itself

Default time for old items (user logon / password set) is 90 days


If you have any suggestions / improvements please let me know.
You're welcome to reach out to me here or via Twitter.
