FROM ubuntu:bionic

ENV FLASK_APP=appscale.cloud_storage \
    APPSCALE_CLOUD_STORAGE_SETTINGS=/opt/appscale-cloud-storage/acs.cfg \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8

RUN apt-get --assume-yes update \
 && apt-get --assume-yes install python3-pip \
 && apt-get --assume-yes clean all \
 && mkdir -pv /opt/appscale-cloud-storage

COPY ./ /root/appscale-cloud-storage

RUN pip3 install /root/appscale-cloud-storage

WORKDIR /opt/appscale-cloud-storage

CMD flask run --host=0.0.0.0

