import { TestBed } from '@angular/core/testing';
import { Socket } from 'ngx-socket-io';
import { of } from 'rxjs';

import { AuthFormat, AuthResponseFormat, AuthService } from './auth-service.service';

describe('AuthServiceService', () => {
  let service: AuthService;
  let socketIO: jasmine.SpyObj<Socket>;
  const loginReturnMock = {
    uid: 'UUID',
    room: 'roomId',
    token: 'TOKEN'
  } as AuthResponseFormat;
  const logoutReturnMock = loginReturnMock as unknown as AuthFormat;
  beforeEach(() => {
    socketIO = jasmine.createSpyObj('Socket', ['emit', 'fromEvent']);
    TestBed.configureTestingModule({
      providers: [
        {
          provide: Socket,
          useValue: socketIO
        }
      ]
    });
    service = TestBed.inject(AuthService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should execute happy path for attemptLogin', () => {
    service.attemptLogin({
      room: 'ROOM',
      timestamp: new Date().toISOString(),
      uid: 'UUID'
    });
    expect(socketIO.emit).toHaveBeenCalled();
  });
  it('should execute happy path for attemptLogout', () => {
    service.attemptLogout({
      room: 'ROOM',
      timestamp: new Date().toISOString(),
      uid: 'UUID'
    });
    expect(socketIO.emit).toHaveBeenCalled();
  });
  it('should subscribe to login event', (done) => {
    socketIO.fromEvent.and.returnValue(of(loginReturnMock));
    service.subscribeLogin().subscribe((loginReturn) => {
      expect(socketIO.fromEvent).toHaveBeenCalled();
      expect(loginReturn).toEqual(loginReturnMock);
      return done();
    });
  });
  it('should subscribe to logout event', (done) => {
    socketIO.fromEvent.and.returnValue(of(logoutReturnMock));
    service.subscribeLogout().subscribe((logoutReturn) => {
      expect(socketIO.fromEvent).toHaveBeenCalled();
      expect(logoutReturn).toEqual(logoutReturnMock);
      return done();
    });
  });
});
