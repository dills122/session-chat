const nodeEnv = process.env.NODE_ENV;

// local env, non-docker
export const isLocal = (): boolean => {
  return !isProd && !isDev;
};

// local env, docker
export const isDev = (): boolean => {
  return nodeEnv.toUpperCase() === 'DEV';
};

//docker prod env
export const isProd = (): boolean => {
  return nodeEnv.toUpperCase() === 'PROD';
};
