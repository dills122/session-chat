FROM ghcr.io/dills122/session-chat:master
WORKDIR /tmp
COPY ../../ .

RUN rm -rf ./common/temp
RUN rush update --purge
RUN mv ./.env ./apps/chat-backend
# RUN chown -R app /tmp
# USER app

CMD ["npm", "--prefix", "./apps/chat-backend/", "run", "start:dev"]
