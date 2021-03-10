# methlab - Malware Email threat hunter
Wanna cook?


METH is a software for analyze (explode content, submit attachement, search url, parse header etc) all email from imap mailbox ad present result do a webpage

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
