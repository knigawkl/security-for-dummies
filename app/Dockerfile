FROM python:3
EXPOSE 5000

WORKDIR /var/www

RUN pip install --upgrade pip

RUN pip install uwsgi
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

COPY . .

ENV FLASK_APP app.py
ENV FLASK_RUN_HOST 0.0.0.0

CMD ["uwsgi", "--ini", "uwsgi.ini"]
