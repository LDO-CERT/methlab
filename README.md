# methlab

Wanna cook?

## Setup

### Run docker image
```
docker-compose -f local.yml up
```

### Execute managment commands
```
docker-compose -f local.yml run --rm django python manage.py makemigrations
docker-compose -f local.yml run --rm django python manage.py migrate
docker-compose -f local.yml run --rm django python manage.py createsuperuser
```

### Add mail monitoring to crontab **
```
docker-compose -f local.yml run --rm django python manage.py monitor
```

### Import Analyzers from cortex
```
docker-compose -f local.yml run --rm django python manage.py cortex_import
```

# Thanks to:
[ioc-fider](https://github.com/fhightower/ioc-finder)

[mail-parser](https://github.com/SpamScope/mail-parser)
