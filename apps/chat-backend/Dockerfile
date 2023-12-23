FROM ghcr.io/dills122/rushjs-base-img:master
WORKDIR /tmp
COPY . .

RUN adduser -S app
RUN rm -rf ./common/temp \
  && rush install -o chat-backend -p \
  && rush build -o chat-backend
RUN mkdir ./prod \
  && rush deploy --project chat-backend --target-folder ./prod \
  && cp ./.env ./prod/apps/chat-backend/
WORKDIR /tmp/prod/apps/chat-backend
RUN chown -R app /tmp/prod
USER app

CMD ["npm", "run", "start:dev"]
