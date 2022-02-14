FROM ghcr.io/dills122/rushjs-base-img:edge
WORKDIR /tmp
COPY ../../ .

RUN adduser -S app
RUN rm -rf ./common/temp \
    && rush install -f api -p \
    && rush build --to api \
    && mv ./.env ./apps/chat-backend
RUN npm i -g @nestjs/cli
RUN chown -R app /tmp/
USER app


CMD ["npm", "--prefix", "./apps/chat-backend/", "run", "start:dev"]
