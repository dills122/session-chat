const { createHash } = require('node:crypto');

const nodeEnv = process.env.NODE_ENV || '';

// local env, non-docker
export const isLocal = (): boolean => {
  return !nodeEnv || nodeEnv.toUpperCase() === 'LOCAL';
};

// local env, docker
export const isDev = (): boolean => {
  return nodeEnv.toUpperCase() === 'DEV';
};

//docker prod env
export const isProd = (): boolean => {
  return nodeEnv.toUpperCase() === 'PROD';
};

export const hashString = (str: string): string => {
  const hash = createHash('sha256');
  hash.update(str);
  const hashStr: string = hash.digest('hex');
  return hashStr;
};

export const trimOrigin = (url: string): string => {
  const parsedUrl = new URL(url);
  return `${parsedUrl.pathname}${parsedUrl.search}${parsedUrl.hash}`;
};
