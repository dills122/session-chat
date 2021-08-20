FROM node:14-alpine
WORKDIR /tmp
COPY ../ .

# Add bash for testing and being able to run shell in container
RUN apk add --update bash && rm -rf /var/cache/apk/*
# RUN adduser -S app
RUN npm install -g @microsoft/rush
RUN rm -rf ./common/temp
RUN rush update --purge
# RUN chown -R app /tmp
# USER app

CMD ["npm", "--prefix", "./apps/chat-backend/", "run", "start:dev"]
