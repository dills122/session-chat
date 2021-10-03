FROM mhart/alpine-node:14
LABEL version="1.0"
LABEL author="Dylan Steele"
LABEL org.opencontainers.image.authors="dylansteele57@gmail.com"
LABEL description="base image for trader tools, rushjs,pm2"

# Add bash for testing and being able to run shell in container
RUN apk add --update bash && rm -rf /var/cache/apk/*
# RUN adduser -S app
RUN npm install -g @microsoft/rush
RUN npm install pm2 -g
