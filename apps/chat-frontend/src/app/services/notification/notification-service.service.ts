import { Injectable } from '@angular/core';
import { NbGlobalPhysicalPosition, NbToastrService } from '@nebular/theme';
import { Socket } from 'ngx-socket-io';
import { tap } from 'rxjs';
import { EventTypes, NotificationFormat, NotificationMapping, NotificationTypes } from 'shared-sdk';

@Injectable({
  providedIn: 'root'
})
export class NotificationServiceService {
  constructor(
    private socket: Socket,
    private toastrService: NbToastrService
  ) {}

  subscribeToNotifications() {
    return this.socket.fromEvent<NotificationFormat>(EventTypes.NOTIFICATION).pipe(
      tap((notification) => {
        //TODO implement additional data object at some point
        this.showNotification(notification.type);
      })
    );
  }

  showNotification(notificationType: NotificationTypes) {
    const notificationData = NotificationMapping[notificationType];
    const { title, message, type } = notificationData;
    switch (type) {
      case 'info':
        return this.showInformationalNotification(message, title);
      case 'danger':
        return this.showErrorNotification(message, title);
      case 'warn':
        return this.showWarningotification(message, title);
    }
  }

  private showInformationalNotification(message: string, title?: string) {
    this.toastrService.info(message, title, {
      position: NbGlobalPhysicalPosition.TOP_RIGHT
    });
  }

  private showErrorNotification(message: string, title?: string) {
    this.toastrService.danger(message, title, {
      position: NbGlobalPhysicalPosition.TOP_RIGHT
    });
  }

  private showWarningotification(message: string, title?: string) {
    this.toastrService.warning(message, title, {
      position: NbGlobalPhysicalPosition.TOP_RIGHT
    });
  }
}
