import { TestBed } from '@angular/core/testing';
import { Socket } from 'ngx-socket-io';

import { NbToastrService } from '@nebular/theme';
import { of } from 'rxjs';
import { NotificationFormat, NotificationTypes } from 'shared-sdk';
import { NotificationServiceService } from './notification-service.service';

describe('NotificationServiceService', () => {
  let service: NotificationServiceService;
  let socketIOMock: jasmine.SpyObj<Socket>;
  let NbToastrMock: jasmine.SpyObj<NbToastrService>;

  beforeEach(() => {
    socketIOMock = jasmine.createSpyObj('Socket', ['emit', 'fromEvent']);
    NbToastrMock = jasmine.createSpyObj('NbToastrService', ['info', 'danger', 'warning']);
    TestBed.configureTestingModule({
      providers: [
        {
          provide: Socket,
          useValue: socketIOMock
        },
        {
          provide: NbToastrService,
          useValue: NbToastrMock
        }
      ]
    });
    service = TestBed.inject(NotificationServiceService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should call showNotification when a socket event is emitted', () => {
    const spy = spyOn(service, 'showNotification');
    socketIOMock.fromEvent.and.returnValue(
      of({
        type: NotificationTypes.NEW_USER,
        room: 'room',
        timestamp: ''
      } as NotificationFormat)
    );
    service.subscribeToNotifications().subscribe();
    expect(spy).toHaveBeenCalled();
  });

  it('should show an info based notification if USER_LEFT type is displayed', () => {
    service.showNotification(NotificationTypes.USER_LEFT);
    expect(NbToastrMock.info).toHaveBeenCalled();
  });
  it('should show an info based notification if NEW_USER type is displayed', () => {
    service.showNotification(NotificationTypes.NEW_USER);
    expect(NbToastrMock.info).toHaveBeenCalled();
  });
  it('should show an danger based notification if LOGIN_ISSUES type is displayed', () => {
    service.showNotification(NotificationTypes.LOGIN_ISSUES);
    expect(NbToastrMock.danger).toHaveBeenCalled();
  });
  it('should show an warn based notification if LOGIN_TIMEOUT type is displayed', () => {
    service.showNotification(NotificationTypes.LOGIN_TIMEOUT);
    expect(NbToastrMock.warning).toHaveBeenCalled();
  });
});
