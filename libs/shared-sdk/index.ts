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
  NEW_USER = 'new-user'
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

export interface NotificationFormat {
  type: NotificationTypes;
  data?: {
    [key: string]: string;
  };
}
