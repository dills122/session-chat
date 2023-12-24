import { Injectable } from '@angular/core';
import { ParticipantPayload } from 'src/app/models/participant-payload';
import { AuthService } from '../auth/auth-service.service';
import { Router } from '@angular/router';
import { SessionStorageService } from '../session-storage/session-storage.service';
import { LinkGenerationService } from '../link-generation/link-generation.service';

@Injectable({
  providedIn: 'root'
})
export class LoginService {
  private uid: string;
  constructor(
    private authService: AuthService,
    private router: Router,
    private sessionStorageService: SessionStorageService,
    private linkGenerateService: LinkGenerationService
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
      timestamp: new Date().toISOString()
    });
  }

  reAuth({ roomId, uid }) {
    this.authService.attemptLogin({
      room: roomId,
      uid: uid,
      timestamp: new Date().toISOString()
    });
  }

  registerLoginCallback(uid: string, timeoutId?: unknown) {
    if (this.uid) {
      this.uid = uid;
    }
    this.authService.subscribeLogin().subscribe((resp) => {
      if (resp.uid === this.uid) {
        this.setupSessionStorage({
          token: resp.token,
          room: resp.room,
          uid: this.uid
        });
        this.router.navigate(['/chat-room']);
      } else {
        console.log('Not correct response');
      }
      if (timeoutId) {
        clearTimeout(timeoutId as string);
      }
    });
  }

  private setupSessionStorage({ room, token, uid }: { room: string; token: string; uid: string }) {
    this.sessionStorageService.setItem('room', room);
    this.sessionStorageService.setItem('jwt_token', token);
    this.sessionStorageService.setItem('uid', uid);
  }
}
