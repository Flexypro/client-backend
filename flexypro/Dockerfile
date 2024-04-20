FROM python:3.10.0-alpine
ENV PYTHONUNBUFFERED 1

RUN pip install --upgrade pip

WORKDIR /backend

COPY ./requirements.txt .
RUN pip install -r requirements.txt

COPY ./flexypro /backend

COPY ./entrypoint.sh /

ENTRYPOINT [ "sh","/entrypoint.sh" ]