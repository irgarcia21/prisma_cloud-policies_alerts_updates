# IMPORTANT: update "API_config.ini" file before running the script. The following fields are currently empty and need to be updated:
```
URL --> introduce your API URL (e.g. "https://api2.eu.prismacloud.io")
ACCESS_KEY_ID --> introduce your Prisma Cloud ACCESS KEY ID
SECRET_KEY --> introduce your Prisma Cloud SECRET KEY
```
    
## Functioning description:

### 1) First exection:

The fist time the script is executed it will only download the current Policies and Alert Rules in Prisma Cloud, as it doesn't have any previous execution to compare results.

- Script output will indicate no previous execution to compare.
> Script output:
```
No previous execution to compare. Pulling current config. Please wait...

Execution finished successfully
```
- A file will be created with Policies and Alert Rules configuration details. Its name will be the moment in which it has been executed.
> File name example:
```
20210907-080322PM.txt
```
- A "metadata.txt" file will be created so the next execution will have the current execution as a reference.
> "metadata.txt" content example:
```
[LAST_EXECUTION]

LAST_FILE_NAME = 20210907-080322PM.txt
```

### 2) Subsequent executions:

Next executions will compare their results with their previous execution by default. To do so, they check "metadata.txt" file to know which output file to compare results with.
- Script output will indicate the differences from last execution.

> Script output example:
```
Previous execution found. Analyzing changes. Please wait...

Policies created:
         NONE

Policies modified:
         policyId "2722d2b4-2637-4ef1-8169-cfc19fdd2ab1" name "policy test"

Policies deleted:
         NONE

Alert Rules created:
         NONE

Alert Rules modified:
         NONE

Alert Rules deleted:
         NONE

Alert Rules impacted by changes in policies:
        AlertId "e694d030-f8b4-40c5-9c51-752ba95a9cbb" Name "Email_to_prod"
                 All modified policies
        AlertId "8eda12a1-68be-4eab-a3a5-0f70363250ad" Name "alert rule test"
                 policyId "2722d2b4-2637-4ef1-8169-cfc19fdd2ab1" name "policy test"
        AlertId "b8e40524-8b71-4622-b98c-c7e53818be6f" Name "email-test"
                 All modified policies

Execution finished successfully
```

- A file will be created with Policies and Alert Rules configuration details. Its name will be the moment in which it has been executed.
> File name example:
```
20210908-080256PM.txt
```
- The "metadata.txt" file will be updated with the current execution.
> "metadata.txt" content example:
```
[LAST_EXECUTION]

LAST_FILE_NAME = 20210908-080256PM.txt
```

## Applicable use cases:

The goal of the script is detecting changes on either policies or alert rules (taking into account as well alert rules can be impacted by changes in the policies they are selecting). The script can be run on a regular basis (e.g. daily) to cover different use cases, such as:

- Validating the reason of changes in received alert rules: If an anomaly is detected on the data sent by an alert rule, it could be because of a change in the Prisma Cloud configuration (e.g. adding/deleting a policy on the alert rule or changing the RQL of a policy). Validating if a configuration change has been done can discard false positives regarding instances alerts.
- Configuration auditing: "metadata.txt" file can be manually changed to compare Prisma Cloud current configuration with a previous configuration rather than the last script execution (e.g. comparing the current Prisma Cloud configuration with previous week configuration).
- Restore previous configuration: as policies and alert rules configuration is stored in output files, a previous configuration regarding policies or alert rules could be retrieved.

