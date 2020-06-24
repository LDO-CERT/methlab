methlab
=======

Wanna cook?

# Setup
## Run docker image
```
docker-compose -f local.yml up
```
## Execute managment commands
```
docker-compose -f local.yml run --rm django python manage.py migrate
docker-compose -f local.yml run --rm django python manage.py createsuperuser
```

## Add mail monitoring to crontab **
```
docker-compose -f local.yml run --rm django python manage.py monitor
```

## Import Analyzers from cortex
```
docker-compose -f local.yml run --rm django python manage.py cortex_import
```