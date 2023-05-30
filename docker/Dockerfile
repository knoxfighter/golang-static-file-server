FROM scratch

COPY static_server /bin/
COPY login.gtpl /
COPY upload.gtpl /

ENTRYPOINT ["/bin/static_server"]
