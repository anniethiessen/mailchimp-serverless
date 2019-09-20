FROM python:3.6.9

MAINTAINER Annie Thiessen <annie.thiessen@miraclechannel.ca>

WORKDIR /application

COPY ./ ./
RUN pip install -r requirements.txt

EXPOSE 80

CMD ["python", "application.py"]
