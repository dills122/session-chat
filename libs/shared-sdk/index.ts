export enum EventTypes {
  SEND = 'chatToServer',
  RECEIVE = 'chatToClient',
  NOTIFICATION = 'notification',
  LOGIN = 'login',
  FAILEDLOGIN = 'failedLogin',
  LOGOUT = 'logout'
}

interface AuthBase {
  room: string;
  uid: string;
  timestamp: string;
  isReAuth?: boolean;
}

export interface AuthFormat extends AuthBase {
  referrer: string;
}

export interface AuthResponseFormat extends AuthBase {
  token: string;
}

export interface MessageFormat {
  message: string;
  room: string;
  uid: string;
  timestamp: string;
  token: string;
}
