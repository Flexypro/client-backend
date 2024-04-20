FROM python:3.10.0-alpine

RUN pip install --upgrade pip

COPY ./requirements.txt .
RUN pip install -r requirements.txt

COPY ./flexypro /backend

WORKDIR /backend

COPY ./entrypoint.sh .

ENTRYPOINT [ "sh","/entrypoint.sh" ]