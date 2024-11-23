import { Injectable } from '@angular/core';
import { ParticipantPayload } from 'src/app/models/participant-payload';
import { AuthService } from '../auth/auth-service.service';
import { Router } from '@angular/router';
import { SessionStorageService } from '../session-storage/session-storage.service';
import { LinkGenerationService } from '../link-generation/link-generation.service';
import { UtilService } from '../util/util.service';

@Injectable({
  providedIn: 'root'
})
export class LoginService {
  private uid: string;
  constructor(
    private authService: AuthService,
    private router: Router,
    private sessionStorageService: SessionStorageService,
    private linkGenerateService: LinkGenerationService,
    private utilService: UtilService
  ) {}

  login(payload: ParticipantPayload) {
    this.uid = payload.uid;
    const isValid = this.linkGenerateService.verifyHash({
      uid: payload.uid,
      roomId: payload.roomId,
      hash: payload.hash
    });
    if (!isValid) {
      return Error('Unable to validate given participant data');
    }
    return this.authService.attemptLogin({
      room: payload.roomId,
      uid: payload.uid,
      // timestamp: new Date().toISOString(),
      referrer: payload.referrer
    });
  }

  reAuth({ roomId, uid }) {
    this.authService.attemptLogin({
      room: roomId,
      uid: uid,
      // timestamp: new Date().toISOString(),
      isReAuth: true,
      referrer: 're-auth'
    });
  }

  registerLoginCallback(uid: string, timeoutId?: unknown) {
    if (this.uid) {
      this.uid = uid;
    }
    this.authService.subscribeLogin().subscribe((resp) => {
      this.utilService.clearTimeoutIfExists(timeoutId as string);
      if (resp.uid === this.uid) {
        if (resp.isReAuth) {
          return;
        }
        if (!resp.token) {
          console.warn('Not correct response');
          return;
        }
        this.setupSessionStorage({
          token: resp.token,
          room: resp.room,
          uid: this.uid
        });
        this.router.navigate(['/chat-room']);
      } else {
        console.warn('Not correct response');
        if (resp.isReAuth) {
          this.router.navigate(['/home']);
        }
      }
    });
  }

  private setupSessionStorage({ room, token, uid }: { room: string; token: string; uid: string }) {
    this.sessionStorageService.setItem('room', room);
    this.sessionStorageService.setItem('jwt_token', token);
    this.sessionStorageService.setItem('uid', uid);
  }
}
