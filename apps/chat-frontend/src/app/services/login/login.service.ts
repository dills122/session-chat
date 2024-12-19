import { Injectable } from '@angular/core';
import { Router } from '@angular/router';
import { tap } from 'rxjs';
import { ParticipantPayload } from 'src/app/models/participant-payload';
import { AuthService } from '../auth/auth-service.service';
import { LinkGenerationService } from '../link-generation/link-generation.service';
import { SessionStorageService } from '../session-storage/session-storage.service';
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
    console.log('Attempting Login on Client:');
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

  cleanUpSession() {
    return this.sessionStorageService.clearSessionStorage();
  }

  registerLoginCallback(uid: string, timeoutId?: unknown) {
    if (this.uid) {
      this.uid = uid;
    }
    return this.authService.subscribeLogin().pipe(
      tap((resp) => {
        this.utilService.clearTimeoutIfExists(timeoutId as string);
        if (resp.uid === this.uid) {
          if (resp.isReAuth) {
            return;
          }
          if (!resp.token) {
            console.warn('Not correct response');
            return;
          }
          this.sessionStorageService.setupSessionStorage({
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
      })
    );
  }
}
