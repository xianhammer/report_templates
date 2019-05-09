# FRED report templates
This repo contain report templates for the FRED forensics tool found at https://www.pinguin.lu/fred.

Developed for an assignment up to a deadline, these template are not yet of a satisfyingly good code quality :)
Hopefully, I will have surplus time to continue developing more report templates.

NOTE These report templates are developed for the Windows version. It seems that there are a few differences between Windows and Linux and though I have tried to make some provisions of hitting both targets, the Linux version may be suffering for now.

For now, following report templates are available:

- SAM_Accounts.qs - List user accounts and group memberships (From the SAM hive).
- SAM_AccountsCompact.qs - Compact list of user accounts and group memberships (From the SAM hive).
- SAM_Groups.qs - List group information (From the SAM hive).
- SOFTWARE_OSVersion.qs - List OS information (From the SOFTWARE hive).

# Installation of scripts
The script are simply copyied to the report_template directory and FRED is re-started.

Windows:
Default installation path is C:\Program Files (x86)\fred\

Linux:
Default installation path is /usr/share/fred
