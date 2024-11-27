import { Injectable } from '@nestjs/common';
import { NotificationFormat, NotificationTypes } from 'shared-sdk';

@Injectable()
export class NotificationService {
  buildNotificationMessage({
    type,
    room,
    data
  }: {
    type: NotificationTypes;
    room: string;
    data?: {
      [key: string]: string;
    };
  }): NotificationFormat {
    return {
      type,
      room,
      timestamp: new Date().toISOString(),
      data
    };
  }
}
