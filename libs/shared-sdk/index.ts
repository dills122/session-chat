export enum EventTypes {
  SEND = 'chatToServer',
  RECEIVE = 'chatToClient',
  NOTIFICATION = 'notification',
  CREATE_SESSION = 'createSession',
  LOGIN = 'login',
  FAILED_LOGIN = 'failedLogin',
  LOGOUT = 'logout'
}

export enum EventStatuses {
  SUCCESS = 'success',
  FAILED = 'failed'
}

export enum NotificationTypes {
  USER_LEFT = 'user-left',
  NEW_USER = 'new-user',
  LOGIN_ISSUES = 'login-issues',
  LOGIN_TIMEOUT = 'login-timeout'
}

export const NotificationMapping: {
  [key in NotificationTypes]: {
    message: string;
    title?: string;
    type: 'info' | 'danger' | 'warn';
  };
} = {
  [NotificationTypes.USER_LEFT]: {
    message: 'A user has left the chat.',
    title: 'User Left',
    type: 'info'
  },
  [NotificationTypes.NEW_USER]: {
    message: 'A new user has joined the chat.',
    title: 'User joined session',
    type: 'info'
  },
  [NotificationTypes.LOGIN_ISSUES]: {
    message: 'Issue verifying participant data',
    title: 'Login Issues',
    type: 'danger'
  },
  [NotificationTypes.LOGIN_TIMEOUT]: {
    message: 'Login is taking awhile, try refreshing',
    title: 'Login Timeout',
    type: 'warn'
  }
};

export interface NotificationFormat {
  type: NotificationTypes;
  room: string;
  timestamp: string;
  data?: {
    [key: string]: string;
  };
}

export interface SessionCreation {
  roomId: string;
  creatorUId: string;
  validParticipantLinks: string[];
}

export interface SessionCreationResponse extends StatusResponseBase {
  room: string;
}

export interface StatusResponseBase {
  status: EventStatuses;
}

interface AuthBase {
  room: string;
  uid: string;
  isReAuth?: boolean;
}

export interface AuthFormat extends AuthBase {
  referrer: string;
}

export interface AuthResponseFormat extends AuthBase, StatusResponseBase {
  token?: string;
}

export interface MessageFormat {
  message: string;
  room: string;
  uid: string;
  timestamp: string;
  token: string;
}
