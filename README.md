# Django API

## Required 
Python version 3.9+
Docker

## Clone the repository
```git clone https://github.com/Flexypro/client-backend.git```
```cd client-backend```

## Create a virtual environment to work from
```virtualenv env```

If you do not have python virtualenv installed, install it
```pip install virtualenv```

## Activate the virtual environment
```source env/bin/activate```

## Navigate to the project root directory
```cd flexypro```
## Install project requirements
```pip install -r requirements.txt```

## Create db table
```python manage.py makemigrations && python manage.py migrate```

## Create a superuser
```python manage.py createsuperuser```

## Runserver to access the API
```python manage.py runserver```

## Websockets & realtime communication
If you want to work with websockets, run redis from docker
```docker run --rm -p 6379:6379 redis:7```
