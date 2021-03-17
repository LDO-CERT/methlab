# METH(lab) - Malware Email threat hunter
_Wanna cook?_

## Desc

METH(lab) is a software designed to analyze (explode content, submit attachment, search url, parse header etc via cortex ) all e-mails and the outcome (of the analysis) is displayed on a webpage.

This tool has been created several years ago to stop suspicious mails from getting into the SOC; the first version of METH could only carry out the following analysis:

- research on VT related to HASH of attachments
- research  on VT related to the URL in the body
- analysis of header anomalies (spf, from forged)
 -analysis of URL on Cuckoo Sandbox 

Once these data had been collected, there was a score that could have been assessed by the analyst.

With the newest version, the analysis engine has been improved; instead of implementing each analysis engine, we have relied on [Cortex](https://github.com/TheHive-Project/Cortex) (by [The Hive Project](https://github.com/TheHive-Project/)) , standardazing the Application Programming Interface and using the already installed engines in Cortex (see this [list](https://github.com/TheHive-Project/Cortex-Analyzers/tree/master/analyzers)).

Moreover, the Graphic User Interface has been entirely redeisgned to enhance its efficiency and to better track the activity (analysis assignment).

![screen](https://user-images.githubusercontent.com/10747900/110641722-9d690780-81b2-11eb-80f4-7b5e36e55957.jpg)



## Setup

### Run docker image
```
docker-compose up
```

### Execute managment commands
```
docker-compose run --rm django python manage.py makemigrations
docker-compose run --rm django python manage.py migrate
docker-compose run --rm django python manage.py createsuperuser
```

### Import Analyzers from cortex
```
docker-compose run --rm django python manage.py cortex_import
```

### Services and ports:
```
8001: meth gui
5432: postgres 
5555: flower
6379: redis
```


# Thanks to:
[ioc-finder](https://github.com/fhightower/ioc-finder)

[mail-parser](https://github.com/SpamScope/mail-parser)
