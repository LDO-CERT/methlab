# methlab

Wanna cook?

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
8000: meth gui
5432: postgres 
5555: flower
6379: redis
```


# Thanks to:
[ioc-fider](https://github.com/fhightower/ioc-finder)

[mail-parser](https://github.com/SpamScope/mail-parser)
