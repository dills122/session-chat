export interface MessageFormat {
  message: string;
  room: string;
  uid: string;
  timestamp: string;
}

export interface AuthFormat {
  room: string;
  uid: string;
  timestamp: string;
}

export interface NotificationMessageFormat {
  type: string;
  room: string;
  uid: string;
  timestamp: string;
}
